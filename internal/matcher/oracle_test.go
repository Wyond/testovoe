//go:build pcre2

package matcher

import (
	"os"
	"path/filepath"
	"testing"
)

// The byte-mode reference must see the known semantic differences and nothing else:
// $ before a final newline (PCRE without DOLLAR_ENDONLY) and . over a multi-byte
// character (one character for us, two bytes for nmap).
func TestOracleFindsKnownDifferences(t *testing.T) {
	probes := filepath.Join(t.TempDir(), "probes")
	os.WriteFile(probes, []byte(`Probe TCP NULL q||
match dollar m|^GET / HTTP/1\.1\r\n\r\nab$|s
match dot m|^.*x.y|s
match same m|^GET /|
`), 0o644)
	r, err := LoadRules(probes, Options{Engine: "go", Excluded: "pcre2"})
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(r)
	paths := streamFiles(t, `[{"method":"GET","url":"/","data":"ab\n"}, {"method":"GET","url":"/","data":"xéy"}, {"method":"GET","url":"/","data":"ab"}]`)
	corpus := filepath.Join(t.TempDir(), "corpus")
	if _, err := Convert([]string{filepath.Dir(paths[0])}, corpus, 1, "jx", 1<<30); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(corpus)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rep, err := Oracle(m, s, []int{0, 1, 2}, 2)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][2]int64{}
	for _, x := range rep.Rules {
		got[x.Service] = [2]int64{x.Missed, x.Extra}
	}
	want := map[string][2]int64{
		"dollar": {1, 0}, // request 0: "ab\n" matches ab$ only in PCRE's default mode
		"dot":    {0, 1}, // request 1: é is one character for us, two bytes for the reference
	}
	if len(got) != len(want) || got["dollar"] != want["dollar"] || got["dot"] != want["dot"] {
		t.Fatalf("disagreements %v, want %v", got, want)
	}
	if rep.PatternDiff != 2 || rep.Requests != 3 {
		t.Fatalf("%d of %d requests differ, want 2 of 3", rep.PatternDiff, rep.Requests)
	}
}
