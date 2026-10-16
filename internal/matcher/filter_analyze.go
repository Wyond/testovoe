package matcher

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"unicode"
	"unicode/utf8"
)

// What a pattern's regexp/syntax tree proves about every request it matches: a literal
// prefix, a required literal, bounds on the length, the possible first and last bytes.
// Each function returns a necessary condition or nothing; nothing is always sound.

// lit is a byte string a match must contain. With fold set, b is lower case and is
// compared ignoring ASCII case; such literals only ever consist of bytes whose Unicode
// case-fold orbit is ASCII (see foldSafe), so that comparison is exact for the engine.
type lit struct {
	b    []byte
	fold bool
}

func (l lit) key() string {
	if l.fold {
		return "i" + string(l.b)
	}
	return "c" + string(l.b)
}

// cond is what analyze proves about one pattern.
type cond struct {
	prefixes []lit // non-nil: anchored at 0 and starts with one of these
	lits     []lit // non-nil: contains one of these
	minLen   int
	maxLen   int            // in bytes; only for patterns anchored at both ends
	last     *[4]uint64     // non-nil: the request is non-empty and ends with one of these bytes
	first    *[4]uint64     // same for the first byte; only for patterns anchored at the start
	confirm  *regexp.Regexp // non-nil: an equivalent, cheaper expression for the fast path
}

func analyze(p *Pattern) cond {
	expr := p.Analysis
	// The tree Go parses from the expression the engine compiled (other engines accept
	// the same syntax), or from the relaxed form of a recovered PCRE rule.
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil || expr == "" {
		return cond{maxLen: 1 << 30} // nothing proven: always a candidate, of any length
	}
	c := cond{minLen: minRunes(re), maxLen: 1 << 30}
	if endAnchored(re) {
		if set, nullable := edgeRunes(re, true); !nullable {
			c.last = &set
		}
		if hi := maxRunes(re); anchored(re) && hi < 1<<28 {
			c.maxLen = 4 * hi // a rune is at most 4 bytes
		}
	}
	if anchored(re) {
		if pre := startLits(re); usable(pre, 1, true) {
			c.prefixes = pre
			return c
		}
		if set, nullable := edgeRunes(re, false); !nullable {
			c.first = &set
		}
	}
	// (?s)^.*X matches exactly when X matches somewhere: with the s flag ".*" accepts
	// any prefix. Go runs the anchored form through its slow general matcher, while the
	// bare X lets it skip ahead to X's literal prefix. The fast path confirms with X;
	// the naive path keeps the original, so the diff between them checks this rewrite.
	if engines[p.Engine].DotMatchesInvalidUTF8 && !p.Recovered && len(re.Sub) > 2 && re.Op == syntax.OpConcat && re.Sub[0].Op == syntax.OpBeginText {
		star := re.Sub[1]
		if star.Op == syntax.OpCapture {
			star = star.Sub[0]
		}
		if star.Op == syntax.OpStar && star.Sub[0].Op == syntax.OpAnyChar {
			tail := &syntax.Regexp{Op: syntax.OpConcat, Sub: re.Sub[2:]}
			if cre, err := regexp.Compile(tail.String()); err == nil {
				c.confirm, re = cre, tail
			}
		}
	}
	if l := requiredLits(re); usable(l, 4, false) {
		c.lits = l
	}
	return c
}

// usable decides whether a literal set is worth indexing; any non-empty set would be
// sound, this is only about cost. Start-of-text prefixes of any length are cheap (one
// table lookup). Contained literals need 4+ bytes for the single-pass scan. Shorter ones
// are searched with bytes.Index one by one, which is only cheap when the first byte is
// rare in HTTP text, so they are accepted only if they start with a control byte
// (NUL and friends). Case-insensitive literals are never short.
func usable(lits []lit, minLen int, prefix bool) bool {
	if len(lits) == 0 || len(lits) > 16 {
		return false
	}
	for _, l := range lits {
		switch {
		case len(l.b) == 0:
			return false
		case len(l.b) >= minLen:
		case l.fold || l.b[0] >= 0x20 || l.b[0] == '\t' || l.b[0] == '\r' || l.b[0] == '\n':
			return false
		}
	}
	return true
}

// foldSafe: under (?i) Go matches a rune against its whole Unicode simple-fold orbit.
// For ASCII that orbit is just the two cases, except k (also U+212A KELVIN SIGN) and
// s (also U+017F LONG S). Those two letters and all non-ASCII runes are left out of
// case-insensitive literals, which keeps "compare ignoring ASCII case" exact.
func foldSafe(r rune) bool {
	return r < 0x80 && r != 'k' && r != 'K' && r != 's' && r != 'S'
}

// literalRuns returns the byte strings a literal node is known to match exactly.
// Case-sensitive: the whole literal as UTF-8 (U+FFFD excluded: it also matches any
// invalid byte). Case-insensitive: every maximal run of foldSafe runes, lower-cased.
func literalRuns(re *syntax.Regexp) []lit {
	if re.Flags&syntax.FoldCase == 0 {
		var b []byte
		for _, r := range re.Rune {
			if r == utf8.RuneError {
				return nil
			}
			b = utf8.AppendRune(b, r)
		}
		if len(b) == 0 {
			return nil
		}
		return []lit{{b: b}}
	}
	var runs []lit
	var cur []byte
	for _, r := range append(slices.Clone(re.Rune), -1) {
		if r >= 0 && foldSafe(r) {
			cur = append(cur, lower(byte(r)))
			continue
		}
		runs = append(runs, lit{cur, true}) // may be empty: keeps "starts with" meaningful
		cur = nil
	}
	return runs
}

// startLit: what a match of this literal node begins with (first run), or nothing.
func startLit(re *syntax.Regexp) []lit {
	if r := literalRuns(re); len(r) > 0 && len(r[0].b) > 0 {
		return r[:1]
	}
	return nil
}

// containedLit: the longest byte string every match of this literal node contains.
func containedLit(re *syntax.Regexp) []lit {
	var best []lit
	for _, r := range literalRuns(re) {
		if len(r.b) > 0 && (best == nil || len(r.b) > len(best[0].b)) {
			best = []lit{r}
		}
	}
	return best
}

func zeroWidth(op syntax.Op) bool {
	switch op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	}
	return false
}

// anchored reports whether every match must start at offset 0. `^A|B` is not anchored:
// the tree is Alternate(Concat(^,A), B) and the second branch can match anywhere.
func anchored(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginText:
		return true
	case syntax.OpCapture, syntax.OpPlus:
		return anchored(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min >= 1 && anchored(re.Sub[0])
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if anchored(s) {
				return true
			}
			if !zeroWidth(s.Op) {
				return false // something may consume input before any ^
			}
		}
	case syntax.OpAlternate:
		for _, s := range re.Sub {
			if !anchored(s) {
				return false
			}
		}
		return len(re.Sub) > 0
	}
	return false
}

// startLits returns literals such that every match begins with one of them, or nil.
// Only meaningful together with anchored(): then the request itself begins with one.
func startLits(re *syntax.Regexp) []lit {
	switch re.Op {
	case syntax.OpLiteral:
		return startLit(re)
	case syntax.OpCapture, syntax.OpPlus:
		return startLits(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return startLits(re.Sub[0])
		}
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if !zeroWidth(s.Op) {
				return startLits(s) // first node that consumes input
			}
		}
	case syntax.OpAlternate:
		var all []lit
		for _, s := range re.Sub {
			l := startLits(s)
			if l == nil {
				return nil // one branch without a known start spoils the OR
			}
			all = append(all, l...)
		}
		return all
	}
	return nil
}

// requiredLits returns literals such that every match contains at least one of them.
// Concat: any one child's requirement is necessary, pick the most selective.
// Alternate: the union over all branches; a branch with no requirement means none.
// Optional parts (?, *, {0,n}) contribute nothing.
func requiredLits(re *syntax.Regexp) []lit {
	switch re.Op {
	case syntax.OpLiteral:
		return containedLit(re)
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLits(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLits(re.Sub[0])
		}
	case syntax.OpConcat:
		var best []lit
		for _, s := range re.Sub {
			if l := requiredLits(s); l != nil && (best == nil || shortest(l) > shortest(best)) {
				best = l
			}
		}
		return best
	case syntax.OpAlternate:
		var all []lit
		for _, s := range re.Sub {
			l := requiredLits(s)
			if l == nil {
				return nil
			}
			all = append(all, l...)
		}
		return all
	}
	return nil
}

func shortest(l []lit) int {
	m := len(l[0].b)
	for _, x := range l {
		m = min(m, len(x.b))
	}
	return m
}

// endAnchored reports whether every match must end at the end of the text.
// Go's $ without (?m) is end of text only (PCRE would also accept a final newline).
func endAnchored(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpEndText:
		return true
	case syntax.OpCapture, syntax.OpPlus:
		return endAnchored(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min >= 1 && endAnchored(re.Sub[0])
	case syntax.OpConcat:
		for i := len(re.Sub) - 1; i >= 0; i-- {
			if endAnchored(re.Sub[i]) {
				return true
			}
			if !zeroWidth(re.Sub[i].Op) {
				return false
			}
		}
	case syntax.OpAlternate:
		for _, s := range re.Sub {
			if !endAnchored(s) {
				return false
			}
		}
		return len(re.Sub) > 0
	}
	return false
}

// edgeRunes returns the bytes a match can end with (last=true) or start with
// (last=false), as a 256-bit set, and whether the expression can match the empty string.
// An ASCII rune is its own byte. A rune above 0x7f, and U+FFFD standing for an invalid
// byte, starts and ends with some byte >= 0x80, so one such possibility adds all 128
// high bytes.
func edgeRunes(re *syntax.Regexp, last bool) (set [4]uint64, nullable bool) {
	add := func(r rune) {
		if r < 0x80 {
			set[r>>6] |= 1 << (r & 63)
		} else {
			set[2], set[3] = ^uint64(0), ^uint64(0)
		}
	}
	union := func(sub *syntax.Regexp) bool {
		s, n := edgeRunes(sub, last)
		for k := range set {
			set[k] |= s[k]
		}
		return n
	}
	all := [4]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
	switch re.Op {
	case syntax.OpLiteral:
		r := re.Rune[0]
		if last {
			r = re.Rune[len(re.Rune)-1]
		}
		add(r)
		if re.Flags&syntax.FoldCase != 0 {
			for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
				add(f)
			}
		}
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1] && r < 0x80; r++ {
				add(r)
			}
			if re.Rune[i+1] >= 0x80 {
				add(0x80)
			}
		}
	case syntax.OpAnyChar:
		set = all
	case syntax.OpAnyCharNotNL:
		set = all
		set[0] &^= 1 << '\n'
	case syntax.OpCapture, syntax.OpPlus:
		return edgeRunes(re.Sub[0], last)
	case syntax.OpStar, syntax.OpQuest:
		union(re.Sub[0])
		return set, true
	case syntax.OpRepeat:
		nullable = union(re.Sub[0]) || re.Min == 0
	case syntax.OpConcat:
		// walk inwards from the edge for as long as everything so far may be empty
		nullable = true
		for i := range re.Sub {
			if !nullable {
				break
			}
			if last {
				i = len(re.Sub) - 1 - i
			}
			nullable = union(re.Sub[i])
		}
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			nullable = union(sub) || nullable
		}
	case syntax.OpNoMatch:
	default: // empty match and zero-width assertions
		nullable = true
	}
	return
}

// maxRunes is an upper bound on the runes a match consumes (1<<30 = unbounded).
func maxRunes(re *syntax.Regexp) int {
	const inf = 1 << 30
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture, syntax.OpQuest:
		return maxRunes(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		return inf
	case syntax.OpRepeat:
		if re.Max < 0 {
			return inf
		}
		return min(re.Max*maxRunes(re.Sub[0]), inf)
	case syntax.OpConcat:
		n := 0
		for _, s := range re.Sub {
			n = min(n+maxRunes(s), inf)
		}
		return n
	case syntax.OpAlternate:
		n := 0
		for _, s := range re.Sub {
			n = max(n, maxRunes(s))
		}
		return n
	}
	return 0
}

// minRunes is a lower bound on the number of runes a match consumes. Each rune of the
// input is at least one byte, so a shorter request cannot match.
func minRunes(re *syntax.Regexp) int {
	const inf = 1 << 30
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		return minRunes(re.Sub[0])
	case syntax.OpRepeat:
		return min(re.Min*minRunes(re.Sub[0]), inf)
	case syntax.OpConcat:
		n := 0
		for _, s := range re.Sub {
			n = min(n+minRunes(s), inf)
		}
		return n
	case syntax.OpAlternate:
		n := inf
		for _, s := range re.Sub {
			n = min(n, minRunes(s))
		}
		return n
	case syntax.OpNoMatch:
		return inf
	}
	return 0 // *, ?, empty-width
}
