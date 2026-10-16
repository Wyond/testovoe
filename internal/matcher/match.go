package matcher

import (
	"math/bits"
	"strconv"
)

// Matcher is immutable after NewMatcher and shared by all workers.
type Matcher struct {
	Rules  *Rules
	Filter *Filter
}

func NewMatcher(r *Rules) *Matcher {
	return &Matcher{Rules: r, Filter: BuildFilter(r)}
}

// Worker is the mutable per-goroutine state. Nothing in it is shared.
type Worker struct {
	cand    []uint64 // candidate bitset over pattern ids
	ids     []uint32 // matched pattern ids, ascending = priority order
	seen    []uint64 // per service: stamp of the last request that listed it (hard / soft)
	seenS   []uint64
	litSeen []uint64 // per literal: stamp of the scan that already reported it
	stamp   uint64   // 64 bits: never wraps, so a zero entry always means "not seen"
	out     []byte

	Stats Stats
}

// Stats are plain local counters, summed once after the workers stop.
type Stats struct {
	Requests, Bytes      int64
	RegexCalls, Matches  int64
	WithMatch            int64
	PrefixCand, LitCand  int64
	LitChecks, LitPasses int64
}

func (s *Stats) add(o Stats) {
	s.Requests += o.Requests
	s.Bytes += o.Bytes
	s.RegexCalls += o.RegexCalls
	s.Matches += o.Matches
	s.WithMatch += o.WithMatch
	s.PrefixCand += o.PrefixCand
	s.LitCand += o.LitCand
	s.LitChecks += o.LitChecks
	s.LitPasses += o.LitPasses
}

func (m *Matcher) NewWorker() *Worker {
	n := len(m.Rules.Patterns)
	return &Worker{
		cand:    make([]uint64, (n+63)/64),
		seen:    make([]uint64, len(m.Rules.Services)),
		seenS:   make([]uint64, len(m.Rules.Services)),
		litSeen: make([]uint64, len(m.Filter.lits)),
	}
}

// MatchNaive runs every supported pattern. It is the reference for MatchFast.
func (m *Matcher) MatchNaive(req []byte, w *Worker) []uint32 {
	w.ids = w.ids[:0]
	in := reqInput{b: req}
	for _, p := range m.Rules.Patterns {
		if in.match(p.Re) {
			w.ids = append(w.ids, p.ID)
		}
	}
	w.Stats.RegexCalls += int64(len(m.Rules.Patterns))
	return w.ids
}

// MatchFast confirms, with the same engine, only the patterns the filter could not rule
// out. Candidates are visited in ascending id, so the result order is the same.
func (m *Matcher) MatchFast(req []byte, w *Worker) []uint32 {
	clear(w.cand)
	m.Filter.candidates(req, w)
	w.ids = w.ids[:0]
	confirm := m.Filter.confirm
	in := reqInput{b: req}
	for wi, x := range w.cand {
		for ; x != 0; x &= x - 1 {
			id := uint32(wi<<6 + bits.TrailingZeros64(x))
			w.Stats.RegexCalls++
			if in.match(confirm[id]) {
				w.ids = append(w.ids, id)
			}
		}
	}
	return w.ids
}

// appendResult serializes one result line:
//
//	{"id":4,"hard":["pc-duo","ventrilo"],"soft":[]}
//
// Service names are listed in priority order, once per kind. A service present in both
// kinds is kept in both. Names were checked to be JSON-safe ASCII when the rules loaded.
func (m *Matcher) appendResult(dst []byte, id int, ids []uint32, w *Worker) []byte {
	w.stamp++
	dst = append(dst, `{"id":`...)
	dst = strconv.AppendInt(dst, int64(id), 10)
	for k, key := range [2]string{`,"hard":[`, `,"soft":[`} {
		dst = append(dst, key...)
		seen, first := w.seen, true
		if Kind(k) == Soft {
			seen = w.seenS
		}
		for _, pid := range ids {
			p := m.Rules.Patterns[pid]
			if p.Kind != Kind(k) || seen[p.ServiceID] == w.stamp {
				continue
			}
			seen[p.ServiceID] = w.stamp
			if !first {
				dst = append(dst, ',')
			}
			first = false
			dst = append(dst, '"')
			dst = append(dst, p.Service...)
			dst = append(dst, '"')
		}
		dst = append(dst, ']')
	}
	return append(dst, '}', '\n')
}
