package matcher

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// SizeProfile answers "what does the heavy tail cost": the request length distribution
// and, per size group, how long the fast path takes on one goroutine. Every request is
// timed separately, which adds a clock read per request; use it to compare groups, not
// as the throughput number.
func SizeProfile(m *Matcher, s *Store) string {
	n := s.Count()
	if n == 0 {
		return "empty corpus\n"
	}
	lens := make([]int, n)
	var total int64
	for i := range lens {
		lens[i] = int(s.Offset(i+1) - s.Offset(i))
		total += int64(lens[i])
	}
	sorted := slices.Clone(lens)
	slices.Sort(sorted)
	pct := func(p float64) int { return sorted[min(n-1, int(p*float64(n)))] }
	var b strings.Builder
	fmt.Fprintf(&b, "request length, bytes: min %d, p50 %d, p90 %d, p95 %d, p99 %d, p99.9 %d, max %d, mean %.0f\n\n",
		sorted[0], pct(.5), pct(.9), pct(.95), pct(.99), pct(.999), sorted[n-1], float64(total)/float64(n))

	limits := []int{1 << 10, 4 << 10, 16 << 10, 64 << 10, 1 << 20, 1 << 62}
	label := []string{"< 1 KB", "1-4 KB", "4-16 KB", "16-64 KB", "64 KB-1 MB", ">= 1 MB"}
	type group struct {
		reqs, bytes, calls int64
		dur                time.Duration
	}
	g := make([]group, len(limits))
	w := m.NewWorker()
	for i := 0; i < n; i++ {
		k := 0
		for lens[i] >= limits[k] {
			k++
		}
		before := w.Stats.RegexCalls
		t := time.Now()
		m.MatchFast(s.Request(i), w)
		g[k].dur += time.Since(t)
		g[k].reqs++
		g[k].bytes += int64(lens[i])
		g[k].calls += w.Stats.RegexCalls - before
	}
	var all time.Duration
	for _, x := range g {
		all += x.dur
	}
	b.WriteString("| size | requests | % requests | % bytes | % time | µs/request | MB/s | regex calls/request |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|\n")
	for k, x := range g {
		if x.reqs == 0 {
			continue
		}
		fmt.Fprintf(&b, "| %s | %d | %.1f | %.1f | %.1f | %.1f | %.0f | %.1f |\n", label[k], x.reqs,
			100*float64(x.reqs)/float64(n), 100*float64(x.bytes)/float64(total), 100*float64(x.dur)/float64(all),
			float64(x.dur.Microseconds())/float64(x.reqs), float64(x.bytes)/1e6/x.dur.Seconds(), float64(x.calls)/float64(x.reqs))
	}
	return b.String()
}
