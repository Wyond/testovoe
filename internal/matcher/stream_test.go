package matcher

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// streamFiles writes the given file contents into a temp dir and returns their paths in
// lexical order, which is the order Convert and RunStream both use.
func streamFiles(t *testing.T, contents ...string) []string {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for i, c := range contents {
		p := filepath.Join(dir, fmt.Sprintf("f%03d.json", i))
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	return paths
}

// Tricky but valid JSON: braces, brackets and escaped quotes inside strings, escapes,
// Unicode, surrogate pairs, numbers, booleans, null, nested values, empty fields,
// whitespace and newlines between elements, and an element larger than any chunk.
func validStreamInputs() []string {
	big := strings.Repeat(`a\"b}{][x`, 40000) // ~360 KB of escapes and structural characters
	return []string{
		`[{"method":"GET","url":"/a?b={c}&d=[e]","headers":{"Host":"x","X-Q":"say \"}\" then \\"},"data":"{\"json\":[1,2]}"}]`,
		"[\n {\"method\": \"POST\", \"url\": \"/\u00e9\\u00e9\\ud83d\\ude00\", \"headers\": {\"A\": 1.50, \"B\": true, \"C\": null, \"D\": {\"x\": [1]}, \"E\": \"\"},\n  \"data\": \"line1\\nline2\\u0000end\\\\\"},\n" +
			` {"method":"","url":"","headers":{},"data":""} , {"url":"/no-method"}, {"method":"GET","url":"/","headers":null,"data":null,"extra":{"skip":["}",{"a":"]"}]}}` + "\n]\n",
		`[]`,
		`[{"method":"PUT","url":"/big","headers":{"Content-Type":"x"},"data":"` + big + `"}, {"method":"GET","url":"/after-big"}]`,
		`[{"method":"GET","url":"/dup","method":"POST","headers":{"K":"1"},"headers":{"K":"2"}}]`,
		// A lone surrogate: encoding/json and jx write U+FFFD, simdjson refuses it and
		// hands the message to jx.
		`[{"method":"GET","url":"/lone\ud800surrogate","headers":{"K":"\udc00"}}]`,
	}
}

func TestStreamMatchesCorpus(t *testing.T) {
	m := testMatcher(t)
	paths := streamFiles(t, validStreamInputs()...)
	corpus := filepath.Join(t.TempDir(), "corpus")
	if _, err := Convert([]string{filepath.Dir(paths[0])}, corpus, 2, "std", 1<<30); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(corpus)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ref, err := Run(m, s, Config{Mode: "naive", Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, parser := range ParserNames() {
		// Normalized bytes must equal the corpus for every id.
		n := 0
		err := StreamNormalized(paths, parser, func(id int64, norm []byte) error {
			if want := s.Request(int(id)); string(norm) != string(want) {
				return fmt.Errorf("id %d:\n got  %.120q\n want %.120q", id, norm, want)
			}
			n++
			return nil
		})
		if err != nil || n != s.Count() {
			t.Fatalf("%s: %v (%d of %d requests)", parser, err, n, s.Count())
		}
		// Results must equal the corpus run, whatever the chunk size and worker count.
		for _, cfg := range []StreamConfig{
			{Parser: parser, Workers: 1},
			{Parser: parser, Workers: 4, ChunkSize: 64, QueueJobs: 2, QueueBytes: 256}, // elements cross chunks, chunks grow
			{Parser: parser, Workers: 3, ChunkSize: 1000},
			{Parser: parser, Workers: 2, Mode: "naive", ChunkSize: 4096},
			{Parser: parser, Workers: 4, Readers: 3, ChunkSize: 64, QueueBytes: 256}, // files in parallel, ids by file position
			{Parser: parser, Workers: 2, Readers: 8, Window: 2, ChunkSize: 100},      // window raised to the reader count
			{Parser: parser, Workers: 1, Readers: 2, ChunkSize: 4096, QueueBytes: 1}, // backpressure on every chunk
		} {
			r, err := RunStream(m, paths, cfg)
			if err != nil {
				t.Fatalf("%s %+v: %v", parser, cfg, err)
			}
			if r.Requests != int64(s.Count()) {
				t.Fatalf("%s %+v: %d requests, want %d", parser, cfg, r.Requests, s.Count())
			}
			r.Result.Hashes = rehash(t, m, s, r) // stream and Run hash with different seeds
			if d, miss := Diff(ref, r.Result); len(d) != 0 || miss != 0 {
				t.Errorf("%s %+v: %d results differ from the corpus run, %d missing", parser, cfg, len(d), miss)
			}
		}
	}
}

// rehash recomputes a stream run's per-id hashes with Run's seed, by running the
// corpus requests through the same matcher; it also checks the stream saw every id.
func rehash(t *testing.T, m *Matcher, s *Store, r *StreamResult) []uint64 {
	t.Helper()
	if len(r.Hashes) != s.Count() {
		t.Fatalf("stream produced %d hashes for %d requests", len(r.Hashes), s.Count())
	}
	for _, h := range r.Hashes {
		if h == 0 {
			t.Fatal("a request id was not processed")
		}
	}
	out, err := Run(m, s, Config{Mode: "fast", Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	return out.Hashes
}

// Many small files and a window as narrow as the reader count: readers wait for the
// window, and results of later files wait in the writer for earlier counts.
func TestStreamReaderWindow(t *testing.T) {
	m := testMatcher(t)
	in := validStreamInputs()
	var files []string
	for i := 0; i < 24; i++ {
		files = append(files, in[i%len(in)])
	}
	paths := streamFiles(t, files...)
	corpus := filepath.Join(t.TempDir(), "corpus")
	if _, err := Convert([]string{filepath.Dir(paths[0])}, corpus, 2, "jx", 1<<30); err != nil {
		t.Fatal(err)
	}
	s, _ := OpenStore(corpus)
	defer s.Close()
	var want strings.Builder
	if _, err := Run(m, s, Config{Mode: "fast", Workers: 1, Out: &want}); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []StreamConfig{
		{Parser: "jx", Workers: 3, Readers: 3, Window: 3, ChunkSize: 64},
		{Parser: "jx", Workers: 1, Readers: 4, Window: 4, ChunkSize: 4096, QueueBytes: 1},
	} {
		var got strings.Builder
		cfg.Out = &got
		if _, err := RunStream(m, paths, cfg); err != nil {
			t.Fatalf("%+v: %v", cfg, err)
		}
		if sortedLines(got.String()) != sortedLines(want.String()) {
			t.Errorf("%+v: output differs from the corpus run", cfg)
		}
	}
}

// The stronger check: the stream's own output lines, compared by id with the corpus run.
func TestStreamOutputLines(t *testing.T) {
	m := testMatcher(t)
	paths := streamFiles(t, validStreamInputs()...)
	corpus := filepath.Join(t.TempDir(), "corpus")
	if _, err := Convert([]string{filepath.Dir(paths[0])}, corpus, 2, "jx", 1<<30); err != nil {
		t.Fatal(err)
	}
	s, _ := OpenStore(corpus)
	defer s.Close()
	var want strings.Builder
	if _, err := Run(m, s, Config{Mode: "fast", Workers: 1, Out: &want}); err != nil {
		t.Fatal(err)
	}
	for _, parser := range ParserNames() {
		var got strings.Builder
		if _, err := RunStream(m, paths, StreamConfig{Parser: parser, Workers: 3, Readers: 3, ChunkSize: 100, Out: &got}); err != nil {
			t.Fatal(err)
		}
		if a, b := sortedLines(got.String()), sortedLines(want.String()); a != b {
			t.Errorf("%s: output differs from the corpus run", parser)
		}
	}
}

func sortedLines(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	for i := range l {
		for j := i + 1; j < len(l); j++ {
			if l[j] < l[i] {
				l[i], l[j] = l[j], l[i]
			}
		}
	}
	return strings.Join(l, "\n")
}

// Broken JSON must stop the run with an error, never become an empty request.
func TestStreamRejectsBrokenJSON(t *testing.T) {
	m := testMatcher(t)
	broken := map[string]string{
		"truncated array":       `[{"method":"GET","url":"/"}`,
		"truncated object":      `[{"method":"GET","url":"/"`,
		"unterminated string":   `[{"method":"GET","url":"/]}`,
		"missing comma":         `[{"method":"GET"} {"method":"GET"}]`,
		"trailing comma":        `[{"method":"GET"},]`,
		"element not object":    `[{"method":"GET"}, "x"]`,
		"not an array":          `{"method":"GET"}`,
		"garbage after array":   `[{"method":"GET"}] x`,
		"bad escape":            `[{"method":"GET","url":"/\q"}]`,
		"bad value":             `[{"method":GET}]`,
		"headers not an object": `[{"method":"GET","headers":"Host: x"}]`,
		"missing colon":         `[{"method" "GET"}]`,
		"bad value, unused key": `[{"method":"GET","x":tru}]`,
		"bad nested value":      `[{"method":"GET","headers":{"A":{"b":nul}}}]`,
		"bad number":            `[{"method":"GET","headers":{"A":1.2.3}}]`,
		"bad literal in data":   `[{"method":"GET","data":nulll}]`,
	}
	for _, parser := range ParserNames() {
		for name, doc := range broken {
			paths := streamFiles(t, `[{"method":"GET","url":"/ok"}]`, doc)
			if _, err := RunStream(m, paths, StreamConfig{Parser: parser, Workers: 2, Readers: 2, ChunkSize: 16}); err == nil {
				t.Errorf("%s / %s: no error", parser, name)
			}
		}
	}
}
