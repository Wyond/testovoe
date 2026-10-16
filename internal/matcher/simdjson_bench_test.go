//go:build simdjson

package matcher

import "testing"

// The fixed price of one cgo transition.
func BenchmarkCgoNoop(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cgoNoop()
	}
}

// simdjson over the same messages as BenchmarkParseMessage, but all of them in one cgo
// call: the difference to BenchmarkParseMessage/simdjson is the per-message transition.
func BenchmarkSimdjsonBatch(b *testing.B) {
	msgs := benchMessages(b)
	var base []byte
	var offs, lens []int
	var total int64
	for _, m := range msgs {
		offs = append(offs, len(base))
		lens = append(lens, len(m))
		base = append(base, m...)
		base = append(base, make([]byte, jsonPadding)...)
		total += int64(len(m))
	}
	p, _ := parsers["simdjson"].New()
	sp := p.(*sjParser)
	out := make([]byte, 64<<20)
	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if sp.sjBatch(base, offs, lens, out) < 0 {
			b.Fatal("simdjson rejected a message")
		}
	}
}
