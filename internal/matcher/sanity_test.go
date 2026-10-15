package matcher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The rule set covers the cases where a careless prefilter loses matches:
// `^A|B`, optional branches, OR vs AND, case folding, bytes vs runes, lengths.
const testProbes = `# comment
Probe TCP NULL q||
match lit m|needle|
match pre m|^220 ProFTPD|
match suf m|bye\r\n$|
match halfanchor m=^AAA|BBB= p/x/
match grp m=^(SSH-|HTTP/)1=
match opt1 m|A*BCD|
match opt2 m|xyz?QQQ|
match optbranch m%(foofoo|.*)%
softmatch either m=(foofoo|barbar)=
match nolitbranch m=(needle|\d\d\d\d)=
match fold m|server: nginx|i
match foldk m|kelvin|i
match dotall m|^a.{3}b|s
match dotline m|^a.{3}b|
match nul m|\0\0|
match xff m|\xff\xfe|
match len111 m|^.{111}|s
match firstclass m|^[0-3]\d [A-Z]{3} \d+|
match firstopt m|^\s*<\?xml|
match firsthigh m|^[\x80-\xff]{2}ok|
match firstdot m|^.[ab]c|
match firstfold m|^[k]elp|i
match endset m|^([^:]*):(\d+):0:?$|
match endany m|^(\w+)=(.+)$|
match endhigh m|^caf\xe9$|
match exact12 m|^[0-9A-F]{12}$|
match endopt m|^ok\n?$|
match endalt m=^(?:yes|no\r\n)$=
match endfold m|^bye k$|i
match dotstar m|^.*<title>Index of (\w+)|s
match dotstarcap m|^(.*)\0end|s
match dotstarline m|^.*tail-on-first-line|
match len264 m|^.{264}$|s
match plus m|(?:ab)+cd|
match rep m|x{3,5}yz|
softmatch lit m|needle|
match lit m|another way to be lit|
Probe UDP Second q|x|
match empty m||
softmatch late m|^GET /late|
match unsupported m|^(?!HTTP)foo|
match unsupported2 m|(a)\1|
`

func testMatcher(t *testing.T) *Matcher {
	t.Helper()
	path := filepath.Join(t.TempDir(), "probes")
	if err := os.WriteFile(path, []byte(testProbes), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := LoadRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.BadLines) != 0 {
		t.Fatalf("unparsed lines: %v", r.BadLines)
	}
	return NewMatcher(r)
}

var testInputs = []string{
	"",
	"needle",
	"xx needle xx",
	"220 ProFTPD 1.3 Server",
	" 220 ProFTPD",
	"so long, bye\r\n",
	"bye\r\n ",
	"AAA", "xxAAA", "BBB", "xxBBBxx", // ^A|B: the second branch is not anchored
	"SSH-1.99", "HTTP/1.1 200", "xHTTP/1",
	"BCD", "AAAABCD", "xyQQQ", "xyzQQQ",
	"anything at all", "foofoo", "barbar", "foobar",
	"1234", "123",
	"Server: NGINX", "server: nginx",
	"kelvin", "KELVIN", "Kelvin", // U+212A KELVIN SIGN folds to k
	"a123b", "a1\n3b", "a\r\n\nb",
	"\x00", "\x00\x00", "x\x00\x00x",
	"\xff\xfe", "ÿþ", "\xc3\xbf\xc3\xbe", // raw bytes vs UTF-8 of U+00FF U+00FE
	strings.Repeat("a", 110), strings.Repeat("a", 111), strings.Repeat("a", 112),
	strings.Repeat("é", 56), strings.Repeat("é", 111), // 112 and 222 bytes, 56 and 111 runes
	strings.Repeat("\xff", 111), // invalid UTF-8: one rune per byte
	strings.Repeat("b", 263), strings.Repeat("b", 264), strings.Repeat("b", 265),
	strings.Repeat("b", 264) + "\n",
	"ababcd", "abcd", "acd", "xxyz", "xxxyz", "xxxxxxyz",
	"GET /late HTTP/1.1\r\n\r\n", "POST /late",
	"host:80:0", "host:80:0:", "host:80:0:\n", "host:80:1", "k=v", "k=v\n", "k=\n", "caf\u00e9", "caf\xe9", "cafe",
	"0123456789AB", "0123456789ABC", "0123456789A\u00e9", "ok", "ok\n", "ok\n\n", "yes", "no\r\n", "no", "yes\n",
	"BYE K", "bye \u212a", "bye k ",
	"12 JAN 2024", "42 JAN 2024", " <?xml", "<?xml", "x<?xml", "\u00e9\u00ffok", "\xff\xfeok", "aaok", "\nac", "xbc", "\u00e9ac",
	"kelp", "\u212aelp", "Kelp", "help",
	"a\nb<title>Index of pub", "<title>Index of ", "\xff\xfe<title>Index of x", "x\n\x00end", "\x00en",
	"x tail-on-first-line", "x\ny tail-on-first-line",
	"another way to be lit and a needle",
	"foo", "aa",
}

func TestFastEqualsNaive(t *testing.T) {
	m := testMatcher(t)
	w := m.NewWorker()
	matched := map[string]bool{}
	for _, in := range testInputs {
		naive := slices.Clone(m.MatchNaive([]byte(in), w))
		fast := m.MatchFast([]byte(in), w)
		if !slices.Equal(naive, fast) {
			t.Errorf("input %.40q: naive %v, fast %v", in, names(m, naive), names(m, fast))
		}
		for _, id := range naive {
			matched[m.Rules.Patterns[id].Service] = true
		}
	}
	// every rule must be exercised positively at least once, otherwise the test proves nothing
	for _, p := range m.Rules.Patterns {
		if !matched[p.Service] {
			t.Errorf("no test input matches %s m|%s|", p.Service, p.Source)
		}
	}
}

func names(m *Matcher, ids []uint32) (out []string) {
	for _, id := range ids {
		out = append(out, m.Rules.Patterns[id].Service)
	}
	return
}

func TestExpectations(t *testing.T) {
	m := testMatcher(t)
	w := m.NewWorker()
	has := func(in, svc string) bool {
		return slices.Contains(names(m, m.MatchFast([]byte(in), w)), svc)
	}
	for _, c := range []struct {
		in, svc string
		want    bool
	}{
		{"xxBBBxx", "halfanchor", true}, // unanchored branch of ^AAA|BBB
		{"xxAAA", "halfanchor", false},
		{"BCD", "opt1", true},      // A* is optional
		{"barbar", "either", true}, // OR, not AND
		{"1234", "nolitbranch", true},
		{"Server: NGINX", "fold", true},
		{"Kelvin", "foldk", true}, // Go folds k with the Kelvin sign
		{"a1\n3b", "dotall", true},
		{"a1\n3b", "dotline", false},
		{"\xff\xfe", "xff", false}, // Go: \xff is U+00FF, not the byte FF
		{"ÿþ", "xff", true},        // documented difference from PCRE
		{strings.Repeat("a", 110), "len111", false},
		{strings.Repeat("a", 111), "len111", true},
		{strings.Repeat("é", 56), "len111", false},                     // 112 bytes but 56 runes
		{strings.Repeat("\xff", 111), "len111", dotMatchesInvalidUTF8}, // RE2: . never takes an invalid byte
		{strings.Repeat("b", 264), "len264", true},
		{strings.Repeat("b", 265), "len264", false},
		{strings.Repeat("b", 264) + "\n", "len264", false}, // Go: $ is end of text only
		{"foo", "unsupported", false},
	} {
		if got := has(c.in, c.svc); got != c.want {
			t.Errorf("%s on %.30q: got %v, want %v", c.svc, c.in, got, c.want)
		}
	}
	if n := len(m.Rules.Unsupported); n != 2 {
		t.Errorf("want 2 unsupported patterns reported, got %d", n)
	}
}

func TestResultLine(t *testing.T) {
	m := testMatcher(t)
	w := m.NewWorker()
	// "lit" is hit by two hard rules and one soft rule: listed once per kind, kept in both.
	ids := m.MatchFast([]byte("GET /late another way to be lit and a needle"), w)
	got := string(m.appendResult(nil, 7, ids, w))
	want := `{"id":7,"hard":["lit","optbranch","nolitbranch","empty"],"soft":["lit","late"]}` + "\n"
	if got != want {
		t.Errorf("got  %swant %s", got, want)
	}
	var v struct {
		ID         int
		Hard, Soft []string
	}
	if err := json.Unmarshal([]byte(got), &v); err != nil {
		t.Fatalf("result line is not JSON: %v", err)
	}
	if got := string(m.appendResult(nil, 0, nil, w)); got != `{"id":0,"hard":[],"soft":[]}`+"\n" {
		t.Errorf("empty result: %s", got)
	}
}

// writeCorpus builds a tiny JSON corpus from the test inputs and converts it.
func writeCorpus(t *testing.T, inputs []string) string {
	t.Helper()
	src, out := t.TempDir(), filepath.Join(t.TempDir(), "corpus")
	type req struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
		Data    string            `json:"data"`
	}
	a, b := []req{}, []req{}
	for i, in := range inputs {
		r := req{"POST", "/p?" + strings.ToValidUTF8(in, "?"), map[string]string{"Host": "x"}, strings.ToValidUTF8(in, "?")}
		if i%2 == 0 {
			a = append(a, r)
		} else {
			b = append(b, r)
		}
	}
	for name, v := range map[string][]req{"a.json": a, "b.json": b, "empty.json": {}} {
		j, _ := json.Marshal(v)
		if err := os.WriteFile(filepath.Join(src, name), j, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Convert([]string{src}, out, 3, "jx", 1<<30); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRunWorkersAndOutput(t *testing.T) {
	m := testMatcher(t)
	dir := writeCorpus(t, testInputs)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Count() != len(testInputs) {
		t.Fatalf("corpus has %d requests, want %d", s.Count(), len(testInputs))
	}
	if got := string(s.Request(0)); got != "POST /p? HTTP/1.1\r\nHost: x\r\n\r\n" {
		t.Errorf("normalization of the first request: %q", got)
	}
	var out bytes.Buffer
	naive, err := Run(m, s, Config{Mode: "naive", Workers: 1, Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	// one line per request, each id exactly once, including requests without matches
	seen := map[int]bool{}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var v struct{ ID int }
		if err := json.Unmarshal([]byte(l), &v); err != nil || seen[v.ID] {
			t.Fatalf("bad or repeated line %q: %v", l, err)
		}
		seen[v.ID] = true
	}
	if len(seen) != s.Count() {
		t.Errorf("%d result lines for %d requests", len(seen), s.Count())
	}
	// batch 3 leaves a short last batch; 4 workers on a tiny corpus race for it
	for _, cfg := range []Config{{Mode: "fast", Workers: 1}, {Mode: "fast", Workers: 4, Batch: 3}, {Mode: "fast", Workers: 8, Batch: 1000},
		{Mode: "fast", Workers: 3, Batch: 5, Access: "mmap"}, {Mode: "naive", Workers: 2, Access: "mmap", Sample: 0}} {
		r, err := Run(m, s, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if d, miss := Diff(naive, r); len(d) != 0 || miss != 0 || r.Duplicates != 0 {
			t.Errorf("%+v: %d lines differ from naive, %d missing, %d duplicates", cfg, len(d), miss, r.Duplicates)
		}
	}
}

func TestStoreRejectsDamage(t *testing.T) {
	dir := writeCorpus(t, testInputs)
	damage := func(name string, f func([]byte) []byte) {
		t.Helper()
		p := filepath.Join(dir, name)
		orig, _ := os.ReadFile(p)
		os.WriteFile(p, f(slices.Clone(orig)), 0o644)
		if s, err := OpenStore(dir); err == nil {
			s.Close()
			t.Errorf("%s damaged but OpenStore succeeded", name)
		}
		os.WriteFile(p, orig, 0o644)
	}
	damage("corpus.bin", func(b []byte) []byte { return b[:len(b)-5] })                      // truncated payload
	damage("corpus.bin", func(b []byte) []byte { b[0] = 'X'; return b })                     // magic
	damage("corpus.idx", func(b []byte) []byte { return b[:len(b)-8] })                      // missing offset
	damage("corpus.idx", func(b []byte) []byte { b[16+8] = 0xff; b[16+9] = 0xff; return b }) // offset out of order
	damage("manifest.json", func(b []byte) []byte { return []byte(`{"format_version":99}`) })
	if s, err := OpenStore(dir); err != nil {
		t.Fatalf("intact corpus: %v", err)
	} else {
		s.Close()
	}
}

func TestConvertRejectsOddHeaders(t *testing.T) {
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "a.json"), []byte(`[{"method":"GET","url":"/real","headers":["url","/evil"]}]`), 0o644)
	if _, err := Convert([]string{src}, filepath.Join(t.TempDir(), "c"), 0, "jx", 1<<30); err == nil {
		t.Error("array-valued headers must be an error, not silently reinterpreted")
	}
}

// A literal found by the 3-gram scan must still be reported after very many requests
// (the per-literal "seen" stamps must not collide with a wrapped counter).
func TestStampDoesNotWrap(t *testing.T) {
	m := testMatcher(t)
	w := m.NewWorker()
	w.stamp = 1<<32 - 2
	for i := 0; i < 4; i++ {
		if ids := m.MatchFast([]byte("xx needle xx"), w); !slices.Contains(names(m, ids), "lit") {
			t.Fatalf("iteration %d: literal pattern lost", i)
		}
		m.appendResult(nil, i, w.ids, w)
	}
}

// Both decoders must produce byte-identical corpora, including escapes, non-ASCII,
// numbers, booleans, null and nested values in odd places.
func TestDecodersAgree(t *testing.T) {
	src := t.TempDir()
	json := `[
 {"method":"POST","url":"/a?q=%41\u00e9\ud83d\ude00","headers":{"Host":"x","X-N":12.50,"X-B":true,"X-Null":null,"X-Obj":{"a":[1,2]},"X-Esc":"tab\tquote\"slash\\\/"},"data":"line1\nline2\u0000end"},
 {"method":"GET","url":"/","headers":null,"data":null,"extra":{"skip":["me"]}},
 {"url":"/no-method","headers":{},"data":""},
 {"method":"GET","url":"/bad\ud800surrogate","headers":{"K":"\u212a"},"data":"\ufffd"}
]`
	os.WriteFile(filepath.Join(src, "a.json"), []byte(json), 0o644)
	var corp [3][]byte
	for i, dec := range []string{"std", "jx", "jxbytes"} {
		out := filepath.Join(t.TempDir(), dec)
		if _, err := Convert([]string{src}, out, 1, dec, 1<<30); err != nil {
			t.Fatalf("%s: %v", dec, err)
		}
		corp[i], _ = os.ReadFile(filepath.Join(out, "corpus.bin"))
	}
	for i := 1; i < len(corp); i++ {
		if !bytes.Equal(corp[0], corp[i]) {
			t.Errorf("decoder %d differs from std:\nstd %q\ngot %q", i, corp[0], corp[i])
		}
	}
}

// A budget smaller than any file must not deadlock: the writer's next file is always
// allowed through.
func TestConvertTinyBudget(t *testing.T) {
	in, out := t.TempDir(), filepath.Join(t.TempDir(), "c")
	for i := 0; i < 5; i++ {
		os.WriteFile(filepath.Join(in, fmt.Sprintf("%d.json", i)), []byte(`[{"method":"GET","url":"/x","headers":{"a":"b"},"data":"needle"}]`), 0o644)
	}
	if _, err := Convert([]string{in}, out, 4, "jx", 1); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(out)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Count() != 5 {
		t.Fatalf("%d requests, want 5", s.Count())
	}
}

func TestEmptyCorpus(t *testing.T) {
	m := testMatcher(t)
	dir := writeCorpus(t, nil)
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := Run(m, s, Config{Mode: "fast", Workers: 4})
	if err != nil || r.Requests != 0 {
		t.Errorf("empty corpus: %v, %d requests", err, r.Requests)
	}
}
