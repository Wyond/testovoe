package matcher

import (
	"fmt"
	"slices"
	"sort"
)

// Building the filter: the per-pattern conditions proven by filter_analyze.go become
// tables and indexes that filter_scan.go consults for every request.

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
	confirm    []Re
	nRewritten int
	nEnd       int
	nFirst     int
}

type gramRef struct{ lit, off int32 }

type prefixEntry struct {
	lit  lit
	pats []uint32
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

func (f *Filter) Report() string {
	entries, biggest := f.nPrefixLit, 0
	for _, r := range f.range2 {
		biggest = max(biggest, int(r[1]-r[0]))
	}
	return fmt.Sprintf("filter: %d patterns behind a start-of-text prefix (%d distinct prefixes, largest two-byte bucket %d), %d behind a required literal (%d distinct literals, %d of them shorter than 4 bytes), %d always candidates; %d patterns also have an end-of-text condition (length bound or last byte), %d a first-byte class; %d patterns of the form (?s)^.*X confirmed as X\n",
		f.nPrefix, entries, biggest, f.nLit, len(f.lits), len(f.short), len(f.always), f.nEnd, f.nFirst, f.nRewritten)
}
