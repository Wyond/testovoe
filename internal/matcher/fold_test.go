package matcher

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"unicode"
)

// Case-insensitive conditions must survive the two ASCII letters whose fold orbit
// leaves ASCII: k ~ U+212A (Kelvin sign) and s ~ U+017F (long s).
func TestFoldConditions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probes")
	os.WriteFile(path, []byte(`Probe TCP NULL q||
match foldpre m|^Task Server ready|i
match foldmid m|^.*<address>Apache/|si
match foldalt m=^(?:ftp ready|KO)=i
match foldlit m|proxy-agent: squid|i
`), 0o644)
	r, err := LoadRules(path)
	if err != nil || len(r.Patterns) != 4 {
		t.Fatal(err, r.BadLines)
	}
	m := NewMatcher(r)
	// foldalt has a branch starting with K, whose orbit is not ASCII: no condition for it.
	if a := m.Filter.always; len(a) != 1 || r.Patterns[a[0]].Service != "foldalt" {
		t.Errorf("expected only foldalt among always-candidates, got %v", a)
	}
	w := m.NewWorker()
	want := map[string]string{
		"task server ready":       "foldpre",
		"TASK SERVER READY":       "foldpre",
		"TaſK ſerver ready":       "foldpre", // long s and Kelvin sign inside the prefix
		"xTask Server ready":      "",
		"<html><ADDRESS>apache/2": "foldmid",
		"<addreſſ>Apache/":        "foldmid",
		"<address>Apach/":         "",
		"FTP READY":               "foldalt",
		"ko":                      "foldalt",
		"KO!":                     "foldalt",
		"ftp read":                "",
		"Proxy-Agent: SQUID":      "foldlit",
		"x PROXY-AGENT: ſQUID":    "foldlit",
		"proxy-agent: sguid":      "",
	}
	for in, svc := range want {
		naive := slices.Clone(m.MatchNaive([]byte(in), w))
		fast := m.MatchFast([]byte(in), w)
		if !slices.Equal(naive, fast) {
			t.Errorf("%q: naive %v, fast %v", in, names(m, naive), names(m, fast))
		}
		if got := slices.Contains(names(m, naive), svc); got != (svc != "") && svc != "" {
			t.Errorf("%q: expected %s to match", in, svc)
		}
		if svc == "" && len(naive) != 0 {
			t.Errorf("%q: expected no match, got %v", in, names(m, naive))
		}
	}
}

// The conditions rely on this property of Unicode simple folding.
func TestFoldSafe(t *testing.T) {
	for r := rune(0); r < 0x80; r++ {
		ascii := true
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			ascii = ascii && f < 0x80
		}
		if !ascii && foldSafe(r) {
			t.Errorf("%q folds outside ASCII but is treated as safe", r)
		}
		if ascii && !foldSafe(r) {
			t.Errorf("%q is excluded although its fold orbit is ASCII", r)
		}
	}
}
