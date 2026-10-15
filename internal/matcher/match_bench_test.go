package matcher

import "testing"

// Allocations and time per request on a sample of the real corpus:
//
//	go test ./internal/matcher -run XXX -bench Match -benchmem
//
// Skipped when data/corpus has not been prepared.
func benchMatch(b *testing.B, fast bool) {
	rules, err := LoadRules("../../data/nmap-service-probes", Options{Engine: testEngine()})
	if err != nil {
		b.Skip("no rules:", err)
	}
	s, err := OpenStore("../../data/corpus")
	if err != nil {
		b.Skip("no corpus:", err)
	}
	defer s.Close()
	m := NewMatcher(rules)
	const sample = 2000
	reqs := make([][]byte, sample)
	var bytes int64
	for i := range reqs {
		reqs[i] = s.Request(i * (s.Count() / sample))
		bytes += int64(len(reqs[i]))
	}
	w := m.NewWorker()
	for _, r := range reqs { // warm up: scratch buffers reach their final size
		m.MatchFast(r, w)
	}
	b.SetBytes(bytes / sample)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := reqs[i%sample]
		var ids []uint32
		if fast {
			ids = m.MatchFast(r, w)
		} else {
			ids = m.MatchNaive(r, w)
		}
		w.out = m.appendResult(w.out[:0], i, ids, w)
	}
}

func BenchmarkMatchFast(b *testing.B)  { benchMatch(b, true) }
func BenchmarkMatchNaive(b *testing.B) { benchMatch(b, false) }
