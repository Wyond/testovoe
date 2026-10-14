package matcher

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"regexp"
	"regexp/syntax"
	"slices"
	"sort"
	"unicode"
	"unicode/utf8"
)

// Filter decides which patterns have to be confirmed for a request.
//
// Invariant: if Pattern.Re matches the request, the pattern is a candidate. Every
// condition below is a necessary condition derived from the regexp/syntax AST of the
// exact expression that was compiled; when nothing can be proven the pattern is an
// always-candidate. False positives cost a regex call, false negatives are bugs.
//
// The confirming engine is Go's regexp on the raw request bytes. It decodes the input
// as UTF-8 (an invalid byte is one U+FFFD), so a literal rune of the pattern can only
// match the canonical UTF-8 bytes of that rune. That is what makes byte-level
// conditions on the raw request sound for this engine.
type Filter struct {
	nPat   int
	always []uint32
	// Per-pattern conditions checked before a pattern becomes a candidate.
	minLen []int32      // a match consumes at least this many runes, hence bytes
	maxLen []int32      // ^...$ patterns: at most this many bytes
	last   []*[4]uint64 // ...$ patterns: allowed final bytes of the request (nil = any)
	first  []*[4]uint64 // ^... patterns without a literal prefix: allowed first bytes

	// Class "prefix": every match starts at offset 0 with one of a few literals.
	// prefixes is sorted; range2[b0<<8|b1] is the run of literals of 2+ bytes starting
	// with those two bytes, one[b] the patterns whose literal is the single byte b.
	prefixes []prefixEntry
	range2   [1 << 16][2]uint32
	one      [256][]uint32

	// Class "literal": every match contains at least one of the pattern's literals.
	// Literals of 4+ bytes are found by one pass of the 3-gram scan (see scan), the few
	// shorter ones by bytes.Index / IndexByte.
	lits    []lit
	litPats [][]uint32
	short   []int32 // indexes into lits searched one by one
	bloom   [1 << 11]uint64
	bucket  [1 << 16]uint32 // top 16 hash bits -> index into grams, +1
	grams   [][]gramRef

	nPrefix, nLit, nPrefixLit int

	// confirm[id] is what MatchFast runs for a candidate: the pattern's own regexp, or
	// for the few rewritten ones an expression proven to match the same inputs.
	confirm    []*regexp.Regexp
	nRewritten int
	nEnd       int
	nFirst     int
}

type gramRef struct{ lit, off int32 }

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

func (l lit) at(req []byte, pos int) bool {
	if pos < 0 || len(req)-pos < len(l.b) {
		return false
	}
	if !l.fold {
		return bytes.Equal(req[pos:pos+len(l.b)], l.b)
	}
	for i, c := range l.b {
		if lower(req[pos+i]) != c {
			return false
		}
	}
	return true
}

func lower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

// variants calls fn with every upper/lower spelling of the first n bytes (n <= 3).
func (l lit) variants(off, n int, fn func(g [3]byte)) {
	for mask := 0; mask < 1<<n; mask++ {
		var g [3]byte
		dup := false
		for i := 0; i < n; i++ {
			g[i] = l.b[off+i]
			if mask>>i&1 == 1 {
				if !l.fold || g[i] < 'a' || g[i] > 'z' {
					dup = true // no distinct upper-case spelling
					break
				}
				g[i] -= 32
			}
		}
		if !dup {
			fn(g)
		}
	}
}

type prefixEntry struct {
	lit  lit
	pats []uint32
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

func BuildFilter(r *Rules) *Filter {
	f := &Filter{nPat: len(r.Patterns), minLen: make([]int32, len(r.Patterns))}
	byPrefix := map[string][]uint32{}
	byLit := map[string][]uint32{}
	lits := map[string]lit{}
	for _, p := range r.Patterns {
		c := analyze(p)
		f.minLen[p.ID] = int32(min(c.minLen, 1<<30))
		f.maxLen = append(f.maxLen, int32(c.maxLen))
		f.last = append(f.last, c.last)
		f.first = append(f.first, c.first)
		if c.first != nil {
			f.nFirst++
		}
		if c.last != nil || c.maxLen < 1<<30 {
			f.nEnd++
		}
		f.confirm = append(f.confirm, p.Re)
		if c.confirm != nil {
			f.confirm[p.ID] = c.confirm
			f.nRewritten++
		}
		switch {
		case c.prefixes != nil:
			f.nPrefix++
			for _, l := range c.prefixes {
				lits[l.key()] = l
				byPrefix[l.key()] = append(byPrefix[l.key()], p.ID)
			}
		case c.lits != nil:
			f.nLit++
			for _, l := range c.lits {
				lits[l.key()] = l
				byLit[l.key()] = append(byLit[l.key()], p.ID)
			}
		default:
			f.always = append(f.always, p.ID)
		}
	}
	// A case-insensitive prefix is filed under every spelling of its first two bytes.
	perKey := map[uint32][]prefixEntry{}
	for _, k := range sortedKeys(byPrefix) {
		l := lits[k]
		f.nPrefixLit++
		if len(l.b) == 1 {
			l.variants(0, 1, func(g [3]byte) { f.one[g[0]] = append(f.one[g[0]], byPrefix[k]...) })
			continue
		}
		l.variants(0, 2, func(g [3]byte) {
			key := uint32(g[0])<<8 | uint32(g[1])
			perKey[key] = append(perKey[key], prefixEntry{l, byPrefix[k]})
		})
	}
	for key := uint32(0); key < 1<<16; key++ {
		if es := perKey[key]; len(es) > 0 {
			f.range2[key] = [2]uint32{uint32(len(f.prefixes)), uint32(len(f.prefixes) + len(es))}
			f.prefixes = append(f.prefixes, es...)
		}
	}
	for _, k := range sortedKeys(byLit) {
		l := lits[k]
		f.lits = append(f.lits, l)
		f.litPats = append(f.litPats, byLit[k])
		li := int32(len(f.lits) - 1)
		if len(l.b) < 4 {
			f.short = append(f.short, li)
			continue
		}
		for off := int32(0); off < 2; off++ {
			l.variants(int(off), 3, func(g [3]byte) {
				h := gramHash(uint32(g[0]) | uint32(g[1])<<8 | uint32(g[2])<<16)
				f.bloom[h>>21] |= 1<<(h>>15&63) | 1<<(h>>9&63)
				if f.bucket[h>>16] == 0 {
					f.grams = append(f.grams, nil)
					f.bucket[h>>16] = uint32(len(f.grams))
				}
				if ref := (gramRef{li, off}); !slices.Contains(f.grams[f.bucket[h>>16]-1], ref) {
					f.grams[f.bucket[h>>16]-1] = append(f.grams[f.bucket[h>>16]-1], ref)
				}
			})
		}
	}
	return f
}

func sortedKeys(m map[string][]uint32) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// candidates sets the bit of every pattern that may match req.
func (f *Filter) candidates(req []byte, w *Worker) {
	n := int32(min(len(req), 1<<30))
	set := func(id uint32) { f.add(req, id, w, n) }
	for _, id := range f.always {
		set(id)
	}
	if len(req) > 0 {
		for _, id := range f.one[req[0]] {
			set(id)
		}
	}
	if len(req) > 1 {
		r := f.range2[uint32(req[0])<<8|uint32(req[1])]
		for i := r[0]; i < r[1]; i++ {
			if e := &f.prefixes[i]; e.lit.at(req, 0) {
				for _, id := range e.pats {
					set(id)
				}
			}
		}
	}
	for _, li := range f.short {
		l := f.lits[li].b // short literals are never case-insensitive, see usable
		var found bool
		if len(l) == 1 {
			found = bytes.IndexByte(req, l[0]) >= 0
		} else {
			found = bytes.Contains(req, l)
		}
		if found {
			for _, id := range f.litPats[li] {
				set(id)
			}
		}
	}
	f.scan(req, w, n)
}

// add makes pattern id a candidate unless its length, first-byte or last-byte condition
// rules it out.
func (f *Filter) add(req []byte, id uint32, w *Worker, n int32) {
	if n < f.minLen[id] || n > f.maxLen[id] {
		return
	}
	if l := f.first[id]; l != nil {
		if n == 0 {
			return
		}
		if b := req[0]; l[b>>6]&(1<<(b&63)) == 0 {
			return
		}
	}
	if l := f.last[id]; l != nil {
		if n == 0 {
			return
		}
		if b := req[len(req)-1]; l[b>>6]&(1<<(b&63)) == 0 { // n is capped, len is not
			return
		}
	}
	w.cand[id>>6] |= 1 << (id & 63)
}

// gramHash mixes three bytes packed into the low 24 bits. Bits 21..31 pick a filter
// word, bits 15..20 and 9..14 two bits inside it: a blocked Bloom filter, one load per test.
func gramHash(v uint32) uint32 { return v * 0x9E3779B1 }

// scan finds all literals of 4+ bytes in one pass over the request.
//
// A literal that starts at position p has its 3-gram at offset 0 at p and its 3-gram at
// offset 1 at p+1; one of the two positions is even. Both grams of every literal are in
// the Bloom filter, so testing every even position cannot miss an occurrence. The filter
// is 16 KB and the lookups for different positions do not depend on each other.
// A position that passes is confirmed by comparing the literal itself.
func (f *Filter) scan(req []byte, w *Worker, n int32) {
	bloom := &f.bloom
	test := func(v uint64) uint64 {
		h := gramHash(uint32(v) & 0xffffff)
		x := bloom[h>>21]
		return x >> (h >> 15 & 63) & (x >> (h >> 9 & 63)) & 1
	}
	w.stamp++
	i := 0
	for ; i+10 <= len(req); i += 8 {
		a := binary.LittleEndian.Uint64(req[i:])   // bytes i .. i+7
		b := binary.LittleEndian.Uint64(req[i+2:]) // bytes i+2 .. i+9
		m := test(a) | test(a>>16)<<2 | test(a>>32)<<4 | test(b>>32)<<6
		for ; m != 0; m &= m - 1 {
			f.checkGram(req, i+bits.TrailingZeros64(m), w, n)
		}
	}
	for ; i+2 < len(req); i += 2 {
		if test(uint64(req[i])|uint64(req[i+1])<<8|uint64(req[i+2])<<16) != 0 {
			f.checkGram(req, i, w, n)
		}
	}
}

func (f *Filter) checkGram(req []byte, i int, w *Worker, n int32) {
	h := gramHash(uint32(req[i]) | uint32(req[i+1])<<8 | uint32(req[i+2])<<16)
	bk := f.bucket[h>>16]
	if bk == 0 {
		return // Bloom false positive
	}
	for _, g := range f.grams[bk-1] {
		if w.litSeen[g.lit] == w.stamp || !f.lits[g.lit].at(req, i-int(g.off)) {
			continue
		}
		w.litSeen[g.lit] = w.stamp
		for _, id := range f.litPats[g.lit] {
			f.add(req, id, w, n)
		}
	}
}

func (f *Filter) Report() string {
	entries, biggest := f.nPrefixLit, 0
	for _, r := range f.range2 {
		biggest = max(biggest, int(r[1]-r[0]))
	}
	return fmt.Sprintf("filter: %d patterns behind a start-of-text prefix (%d distinct prefixes, largest two-byte bucket %d), %d behind a required literal (%d distinct literals, %d of them shorter than 4 bytes), %d always candidates; %d patterns also have an end-of-text condition (length bound or last byte), %d a first-byte class; %d patterns of the form (?s)^.*X confirmed as X\n",
		f.nPrefix, entries, biggest, f.nLit, len(f.lits), len(f.short), len(f.always), f.nEnd, f.nFirst, f.nRewritten)
}

func analyze(p *Pattern) cond {
	expr := p.Source
	if p.Flags != "" {
		expr = "(?" + p.Flags + ")" + expr
	}
	// Same flags as regexp.Compile, so this is the tree the engine was built from.
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return cond{}
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
	if len(re.Sub) > 2 && re.Op == syntax.OpConcat && re.Sub[0].Op == syntax.OpBeginText {
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
