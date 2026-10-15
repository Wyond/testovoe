package matcher

import (
	"fmt"
	"math/bits"
	"slices"
	"strings"
	"time"
)

// CalibrationRow is the measured cost of one rule on the calibration sample.
type CalibrationRow struct {
	Line     int
	Service  string
	Calls    int64            // times the rule survived the prefilter
	Nanos    map[string]int64 // total confirmation time per engine
	Disagree int64            // calls where some engine answered differently from Go
	Chosen   string
}

// Calibrate decides per rule which engine confirms it, by measurement rather than by
// the look of the expression: a long regex may fail on the first byte, a short one may
// walk a whole body, an expensive one may almost never pass the prefilter.
//
// For `sample` requests (every Count/sample-th, starting at offset, so the set is
// disjoint from the baseline sample at offset 0) it runs every candidate rule on every
// engine, rotating the order so no engine always pays for the first touch of the bytes.
// A rule moves off Go only if another engine was faster by at least minGain overall and
// saved at least minSaved in total, and never if any engine disagreed with Go.
func Calibrate(m *Matcher, s *Store, names []string, sample, offset int) ([]CalibrationRow, map[int]string, error) {
	const minGain, minSaved = 0.8, 200 * time.Microsecond
	if !slices.Contains(names, "go") {
		names = append([]string{"go"}, names...)
	}
	pats := m.Rules.Patterns
	res := make([][]Re, len(pats)) // per pattern, per engine
	for id, p := range pats {
		res[id] = make([]Re, len(names))
		for k, n := range names {
			e := engines[n]
			if e == nil {
				return nil, nil, fmt.Errorf("engine %q is not compiled in", n)
			}
			if n == "go" {
				res[id][k] = m.Filter.confirm[id] // what the fast path really runs
				continue
			}
			if p.Recovered {
				continue
			}
			if re, err := e.Compile(p.Analysis); err == nil {
				res[id][k] = re
			}
		}
	}
	rows := make([]CalibrationRow, len(pats))
	for id, p := range pats {
		rows[id] = CalibrationRow{Line: p.Line, Service: p.Service, Nanos: map[string]int64{}}
	}
	w := m.NewWorker()
	stride := max(s.Count()/max(sample, 1), 1)
	order := make([]int, len(names))
	for k := 0; k < sample && k*stride+offset < s.Count(); k++ {
		req := s.Request(k*stride + offset)
		clear(w.cand)
		m.Filter.candidates(req, w)
		for i := range order {
			order[i] = (i + k) % len(names)
		}
		for wi, x := range w.cand {
			for ; x != 0; x &= x - 1 {
				id := wi*64 + bits.TrailingZeros64(x)
				row := &rows[id]
				row.Calls++
				var want, differ bool
				for j, k := range order {
					re := res[id][k]
					if re == nil {
						continue
					}
					t := time.Now()
					got := re.Match(req)
					row.Nanos[names[k]] += int64(time.Since(t))
					if j == 0 {
						want = got
					} else if got != want {
						differ = true
					}
				}
				if differ {
					row.Disagree++
				}
			}
		}
	}
	choice := map[int]string{}
	for id := range rows {
		r := &rows[id]
		r.Chosen = "go"
		goNs := r.Nanos["go"]
		for _, n := range names {
			ns, ok := r.Nanos[n]
			if n == "go" || !ok || r.Disagree > 0 || res[id][slices.Index(names, n)] == nil {
				continue
			}
			best := r.Nanos[r.Chosen]
			if float64(ns) < minGain*float64(goNs) && time.Duration(goNs-ns) >= minSaved && ns < best {
				r.Chosen = n
			}
		}
		if r.Chosen != "go" {
			choice[r.Line] = r.Chosen
		}
	}
	return rows, choice, nil
}

// CalibrationReport lists the rules that cost the most on the sample.
func CalibrationReport(rows []CalibrationRow, names []string, top int) string {
	idx := make([]int, len(rows))
	for i := range idx {
		idx[i] = i
	}
	slices.SortFunc(idx, func(a, b int) int { return int(rows[b].Nanos["go"] - rows[a].Nanos["go"]) })
	var b strings.Builder
	fmt.Fprintf(&b, "| line | service | calls | %s | chosen | disagree |\n", strings.Join(names, " ms | ")+" ms")
	b.WriteString("|---:|---|---:|" + strings.Repeat("---:|", len(names)) + "---|---:|\n")
	var total = map[string]int64{}
	for _, r := range rows {
		for n, ns := range r.Nanos {
			total[n] += ns
		}
	}
	for _, i := range idx[:min(top, len(idx))] {
		r := rows[i]
		fmt.Fprintf(&b, "| %d | %s | %d |", r.Line, r.Service, r.Calls)
		for _, n := range names {
			fmt.Fprintf(&b, " %.1f |", float64(r.Nanos[n])/1e6)
		}
		fmt.Fprintf(&b, " %s | %d |\n", r.Chosen, r.Disagree)
	}
	fmt.Fprintf(&b, "| all | | |")
	for _, n := range names {
		fmt.Fprintf(&b, " %.1f |", float64(total[n])/1e6)
	}
	b.WriteString(" | |\n")
	return b.String()
}
