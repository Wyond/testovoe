package matcher

import (
	"fmt"
	"math/rand"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// rulesFrom builds Rules directly from (source, flags) pairs, the way LoadRules would.
func rulesFrom(t testing.TB, specs [][2]string) *Rules {
	t.Helper()
	r := &Rules{}
	for _, sp := range specs {
		expr := sp[0]
		if sp[1] != "" {
			expr = "(?" + sp[1] + ")" + expr
		}
		re, err := compileRegexp(expr)
		if err != nil {
			continue
		}
		id := uint32(len(r.Patterns))
		r.Patterns = append(r.Patterns, &Pattern{ID: id, Service: fmt.Sprintf("p%d", id), ServiceID: id, Source: sp[0], Flags: sp[1], Re: re})
		r.Services = append(r.Services, fmt.Sprintf("p%d", id))
	}
	return r
}

// diff asserts the invariant on every input: a pattern that matches is a candidate and
// the fast path returns exactly what the naive path returns.
func diff(t *testing.T, m *Matcher, inputs []string) (positives int) {
	t.Helper()
	w := m.NewWorker()
	for _, in := range inputs {
		naive := slices.Clone(m.MatchNaive([]byte(in), w))
		fast := m.MatchFast([]byte(in), w)
		positives += len(naive)
		if !slices.Equal(naive, fast) {
			for _, id := range naive {
				if !slices.Contains(fast, id) {
					p := m.Rules.Patterns[id]
					t.Errorf("lost match: pattern %q flags %q on input %q", p.Source, p.Flags, in)
				}
			}
		}
	}
	return
}

// А. Length and edge-byte bounds are in runes for Go and must be converted to bytes
// conservatively: one rune is 1..4 bytes, an invalid byte is one rune.
func TestRuneLengthBounds(t *testing.T) {
	m := NewMatcher(rulesFrom(t, [][2]string{
		{`^.$`, "s"}, {`^.{2}$`, "s"}, {`^..$`, ""}, {`^[а-я]$`, ""}, {`^\x{1F600}$`, ""},
		{`^я`, ""}, {`я$`, ""}, {`^[а-я]+$`, ""}, {`^Ж`, "i"}, {`ж$`, "i"}, {`[^a]$`, ""},
		{`^\pL{3}$`, ""}, {`^.{1,2}x$`, "s"},
	}))
	inputs := []string{"", "a", "я", "яя", "\U0001F600", "\U0001F600\U0001F600", "\xff", "\xff\xfe", "\xd1",
		"ab", "абв", "Жук", "жук", "ЖУК", "уж", "УЖ", "ёж", "xé", "ééx", "\U0001F600яx", "aяx"}
	diff(t, m, inputs)
	w := m.NewWorker()
	want := map[string]string{"я": "p0", "\U0001F600": "p0", "яя": "p1", "\U0001F600яx": "p12"}
	if dotMatchesInvalidUTF8 {
		want["\xff"] = "p0" // Go only: an invalid byte is one U+FFFD rune
	}
	for in, want := range want {
		if !slices.Contains(names(m, m.MatchFast([]byte(in), w)), want) {
			t.Errorf("%q should match %s", in, want)
		}
	}
}

// Б. The scan tests only even positions; every literal of 4+ bytes must still be found
// at every offset, including the first and last possible one.
func TestLiteralAtEveryOffset(t *testing.T) {
	lits := []string{"abcd", "abcde", "x-ab-y", "\x00\x01\x02\x03", "1234567", "server: ", "<title>"}
	var specs [][2]string
	for _, l := range lits {
		specs = append(specs, [2]string{regexp.QuoteMeta(l), ""}, [2]string{"(?:" + regexp.QuoteMeta(l) + ")", "i"})
	}
	m := NewMatcher(rulesFrom(t, specs))
	if len(m.Filter.always) != 0 {
		t.Fatalf("every literal pattern should be behind the scan, %d are always", len(m.Filter.always))
	}
	var inputs []string
	for _, l := range lits {
		for pre := 0; pre < 13; pre++ {
			for post := 0; post < 11; post++ {
				inputs = append(inputs, strings.Repeat("z", pre)+l+strings.Repeat("y", post))
				inputs = append(inputs, strings.Repeat("я", pre)+strings.ToUpper(l)+strings.Repeat("\xff", post))
			}
		}
	}
	if diff(t, m, inputs) < len(inputs) {
		t.Errorf("expected every input to match at least one literal pattern")
	}
}

// В. Case-insensitive literals: k and s are cut out, never glued. "abksxyz" gives the
// runs "ab" and "xyz"; a glued "abxyz" would reject "ABKSXYZ" and "abKſxyz".
func TestFoldRunsAreContiguous(t *testing.T) {
	m := NewMatcher(rulesFrom(t, [][2]string{{`abksxyz`, "i"}, {`proxy-kit`, "i"}, {`(?:ask)+desk`, "i"}}))
	for _, l := range m.Filter.lits {
		for _, bad := range []string{"abxyz", "proxy-it", "adede"} {
			if string(l.b) == bad {
				t.Errorf("glued literal %q", l.b)
			}
		}
	}
	diff(t, m, []string{"ABKSXYZ", "abKſxyz", "abxyz", "ABKSXYZ", "PROXY-KIT", "proxy-kit",
		"ASKDESK", "aſkdeſK", "askaskdesk", "deskask"})
	w := m.NewWorker()
	for _, in := range []string{"abKſxyz", "PROXY-KIT", "aſKdeſK"} {
		if len(m.MatchFast([]byte(in), w)) == 0 {
			t.Errorf("%q must match", in)
		}
	}
}

// Г. (?s)^.*X -> X is applied only to that AST shape and must stay equivalent.
func TestDotStarRewrite(t *testing.T) {
	specs := [][2]string{
		{`^.*foo`, "s"},       // rewritten
		{`^.*?foo`, "s"},      // lazy star: rewritten
		{`^(.*)foo`, "s"},     // captured star: rewritten
		{`(?:^.*foo)`, "s"},   // group dissolves into the same Concat: rewritten
		{`^.*^foo`, "s"},      // inner ^ keeps meaning "offset 0"
		{`^.*\bfoo`, "s"},     // word boundary after the star
		{`^.*(?m:^)foo`, "s"}, // line start after the star
		{`^.*foo|bar`, "s"},   // top level is an alternation: not rewritten
		{`^.*foo`, ""},        // no s flag: . stops at newline, not rewritten
		{`^(?-s:.*)foo`, "s"}, // star without s inside: not rewritten
		{`^.+foo`, "s"},       // plus, not star: not rewritten
		{`^.*foo$`, "s"},      // end anchor stays in X
		{`^.*\x{FFFD}`, "s"},  // X matches invalid bytes
		{`^.*(?:a|b)c`, "s"},
	}
	m := NewMatcher(rulesFrom(t, specs))
	notRewritten := map[string]bool{`^.*foo|bar`: true, `^(?-s:.*)foo`: true, `^.+foo`: true}
	for id, p := range m.Rules.Patterns {
		want := dotMatchesInvalidUTF8 && p.Flags == "s" && !notRewritten[p.Source]
		if got := m.Filter.confirm[id] != p.Re; got != want {
			t.Errorf("%q flags %q: rewritten=%v, want %v", p.Source, p.Flags, got, want)
		}
	}
	inputs := []string{"", "foo", "xfoo", "x\nfoo", "\nfoo", "afoo", "a foo", "x\xfffoo", "bar", "xbar", "foo\n", "\xff",
		"ac", "x\nbc", "foobar", "a\n\nfoo", "é foo", "éfoo"}
	diff(t, m, inputs)
}

// Randomized differential test: random patterns from tricky pieces, random inputs that
// reuse the same pieces plus invalid UTF-8. Fixed seed, so failures are reproducible.
func TestRandomPatternsNaiveEqualsFast(t *testing.T) {
	atoms := []string{"a", "b", "k", "s", "K", "S", "я", "é", `\x{212A}`, `\x{17F}`, ".", "[a-c]", "[^a]", `\d`, `\w`, `\s`,
		`\b`, "^", "$", `\A`, `\z`, `\x00`, "abcd", "kelvin", "Server: ", "<title>", `\x{FFFD}`, `[а-я]`, `\pL`, "\\\n", "(?i:ks)", "(?s:.)"}
	pieces := []string{"a", "b", "k", "s", "K", "S", "я", "é", "K", "ſ", "x", "\n", "\r\n", "\x00", "\xff", "\xc3",
		"abcd", "kelvin", "KELVIN", "Server: ", "SERVER: ", "<title>", "1", " ", "\U0001F600"}
	rng := rand.New(rand.NewSource(1))
	var gen func(depth int) string
	gen = func(depth int) string {
		if depth == 0 || rng.Intn(3) == 0 {
			return atoms[rng.Intn(len(atoms))]
		}
		switch rng.Intn(7) {
		case 0, 1:
			return gen(depth-1) + gen(depth-1)
		case 2:
			return "(?:" + gen(depth-1) + "|" + gen(depth-1) + ")"
		case 3:
			return "(?:" + gen(depth-1) + ")" + []string{"*", "+", "?", "{0,2}", "{2}", "*?", "{1,3}"}[rng.Intn(7)]
		case 4:
			return "(" + gen(depth-1) + ")"
		case 5:
			return "^" + gen(depth-1)
		default:
			return gen(depth-1) + "$"
		}
	}
	flags := []string{"", "i", "s", "is"}
	for round := 0; round < 20; round++ {
		var specs [][2]string
		for i := 0; i < 300; i++ {
			p := gen(4)
			if rng.Intn(4) == 0 {
				p = "^.*" + p
			}
			specs = append(specs, [2]string{p, flags[rng.Intn(len(flags))]})
		}
		m := NewMatcher(rulesFrom(t, specs))
		var inputs []string
		for i := 0; i < 300; i++ {
			var b strings.Builder
			for n := rng.Intn(8); n > 0; n-- {
				b.WriteString(pieces[rng.Intn(len(pieces))])
			}
			inputs = append(inputs, b.String())
		}
		diff(t, m, inputs)
		if t.Failed() {
			t.Fatalf("round %d failed", round)
		}
	}
}
