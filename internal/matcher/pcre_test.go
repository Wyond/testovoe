package matcher

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Rules Go cannot compile, run on PCRE2 behind a prefilter built from their relaxed
// form. The relaxed language must contain the PCRE one, so naive == fast.
func TestRecoveredRulesNaiveEqualsFast(t *testing.T) {
	if engines["pcre2"] == nil {
		t.Skip("built without -tags pcre2")
	}
	path := filepath.Join(t.TempDir(), "probes")
	os.WriteFile(path, []byte(`Probe TCP NULL q||
match neg m=^(?!HTTP|RTSP).{8}$=s
match look m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?Server: nginx|s
match behind m|(?<=x)abc|
match atomic m|^(?>a+)b|
match poss m|^a*+b|
match backref m=^(\w+) \1$=
match vspace m|^a\sb$|
match hspace m|^a\hb$|
match zend m|ok\Z|
match quote m|^\Q.*+\E!|
match named m|^(?<n>ab)\k<n>$|
match plain m|^GET /|
`), 0o644)
	r, err := LoadRules(path, Options{Engine: "go", Excluded: "pcre2"})
	if err != nil {
		t.Fatal(err)
	}
	recovered := 0
	for _, p := range r.Patterns {
		if p.Recovered {
			recovered++
			if p.Analysis == "" {
				t.Errorf("%s: no relaxed form, prefilter cannot help", p.Service)
			}
		}
	}
	// \s, \Q..\E and plain rules compile in Go and stay on it; the other nine need PCRE.
	if recovered != 9 || len(r.Unsupported) != 0 || len(r.BadLines) != 0 {
		t.Fatalf("recovered %d, unsupported %d: %s", recovered, len(r.Unsupported), r.Report())
	}
	m := NewMatcher(r)
	w := m.NewWorker()
	inputs := []string{"", "abcdefgh", "HTTP/1.", "RTSP/1.0", "abcdefgh\n", "HTTP/1.1 200 OK\r\nDate: x\r\nServer: nginx\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\nServer: nginx", "xabc", "yabc", "aaab", "b", "aab", "foo foo", "foo bar", "a\x0bb", "a\tb",
		"a b", "a\nb", "ok", "ok\n", "ok\n\n", ".*+!", "abab", "abba", "GET /x", "\xff\xfe", "\xffabc", "x\xffabc"}
	matched := map[string]bool{}
	for _, in := range inputs {
		naive := slices.Clone(m.MatchNaive([]byte(in), w))
		fast := m.MatchFast([]byte(in), w)
		if !slices.Equal(naive, fast) {
			t.Errorf("%q: naive %v, fast %v", in, names(m, naive), names(m, fast))
		}
		for _, id := range naive {
			matched[m.Rules.Patterns[id].Service] = true
		}
	}
	for _, p := range r.Patterns {
		if !matched[p.Service] {
			t.Errorf("no input matches %s m|%s|", p.Service, p.Source)
		}
	}
}

// Catastrophic backtracking must stop at the limit and be counted, not hang.
func TestPCRE2Limit(t *testing.T) {
	e := engines["pcre2"]
	if e == nil {
		t.Skip("built without -tags pcre2")
	}
	re, err := e.CompilePCRE(`^(a+)+$`, "")
	if err != nil {
		t.Fatal(err)
	}
	before := Inconclusive()
	if re.Match([]byte(strings.Repeat("a", 40) + "b")) {
		t.Error("should not match")
	}
	if Inconclusive() == before {
		t.Error("the match limit was not reported as inconclusive")
	}
}
