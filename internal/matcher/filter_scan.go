package matcher

import (
	"bytes"
	"encoding/binary"
	"math/bits"
)

// The hot path: which patterns may match this request. Runs once per request in every
// worker; it only reads the Filter, and writes the worker's own candidate bits.

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
