package matcher

import (
	"bufio"
	"fmt"
	"hash/maphash"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Mode    string // "naive" or "fast"
	Workers int
	Sample  int       // 0 = whole corpus; otherwise this many requests spread evenly (every Count/Sample-th)
	Batch   int       // ids claimed per atomic add
	Out     io.Writer // JSONL, one line per request, arbitrary order; nil = discard after formatting
	Access  string    // how workers get request bytes: "mmap" (default) or "pread"
}

type Result struct {
	Engine     string  `json:"engine"`
	Mode       string  `json:"mode"`
	Access     string  `json:"access"`
	Workers    int     `json:"workers"`
	GOMAXPROCS int     `json:"gomaxprocs"`
	Requests   int64   `json:"requests"`
	Bytes      int64   `json:"payload_bytes"`
	Seconds    float64 `json:"matching_with_output_seconds"`
	ReqPerSec  float64 `json:"req_per_sec"`
	MBPerSec   float64 `json:"mb_per_sec"`
	RegexCalls float64 `json:"regex_calls_per_request"`
	Matches    int64   `json:"pattern_matches"`
	WithMatch  int64   `json:"requests_with_match"`
	Stats      Stats   `json:"-"`

	// Hashes[k] is a hash of the output line of the k-th processed request (k indexes the
	// sample). It lets two runs be compared per request without sorting their outputs.
	Hashes []uint64 `json:"-"`
	// Duplicates counts requests that were processed more than once (must stay 0).
	Duplicates int64 `json:"-"`
}

var hashSeed = maphash.MakeSeed()

// Run processes the corpus (or an evenly spread sample of it) on cfg.Workers goroutines.
//
// Work is handed out by one shared atomic cursor: a worker claims the next cfg.Batch ids,
// reads those requests straight from the mapping and keeps everything mutable local.
// A claim only means "someone took this range", not "it is done".
//
// The timed region covers matching, result formatting and the final flush of cfg.Out
// (no fsync). Rule compilation and opening the corpus are outside.
func Run(m *Matcher, s *Store, cfg Config) (*Result, error) {
	if cfg.Workers < 1 {
		cfg.Workers = runtime.NumCPU()
	}
	if cfg.Batch < 1 {
		cfg.Batch = 256
	}
	total, stride := s.Count(), 1
	if cfg.Sample > 0 && cfg.Sample < total {
		stride = total / cfg.Sample
		total = cfg.Sample
	}
	fast := cfg.Mode == "fast"
	if !fast && cfg.Mode != "naive" {
		return nil, fmt.Errorf("unknown mode %q", cfg.Mode)
	}
	if cfg.Access == "" {
		cfg.Access = "mmap"
	}
	if cfg.Access != "pread" && cfg.Access != "mmap" {
		return nil, fmt.Errorf("unknown access %q", cfg.Access)
	}
	// pread copies one contiguous run per batch, so it needs consecutive ids and a batch
	// that fits a sane buffer; a spread-out sample or a huge batch falls back to the mapping.
	pread := cfg.Access == "pread" && stride == 1
	if !pread {
		cfg.Access = "mmap"
	}
	const maxBatchBytes = 64 << 20
	res := &Result{Engine: EngineName, Mode: cfg.Mode, Workers: cfg.Workers, Access: cfg.Access, Hashes: make([]uint64, total)}
	old := runtime.GOMAXPROCS(cfg.Workers)
	defer runtime.GOMAXPROCS(old)
	res.GOMAXPROCS = cfg.Workers

	var out *bufio.Writer
	if cfg.Out != nil {
		out = bufio.NewWriterSize(cfg.Out, 1<<20)
	}
	var (
		next     atomic.Int64
		dups     atomic.Int64
		outMu    sync.Mutex // guards out: taken once per batch, never per request
		writeErr error
		readErr  atomic.Pointer[error]
		wg       sync.WaitGroup
		stats    = make([]Stats, cfg.Workers)
	)
	start := time.Now()
	for wi := 0; wi < cfg.Workers; wi++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := m.NewWorker()
			var buf []byte
			for {
				end := next.Add(int64(cfg.Batch))
				begin := end - int64(cfg.Batch) // Add returns the new position
				if begin >= int64(total) {
					break
				}
				end = min(end, int64(total))
				w.out = w.out[:0]
				var base uint64
				copied := pread && s.Offset(int(end))-s.Offset(int(begin)) <= maxBatchBytes
				if copied {
					var err error
					if buf, base, err = s.ReadRange(int(begin), int(end), buf); err != nil {
						readErr.CompareAndSwap(nil, &err)
						return
					}
				}
				for k := begin; k < end; k++ {
					id := int(k) * stride
					var req []byte
					if copied {
						req = buf[s.Offset(id)-base : s.Offset(id+1)-base]
					} else {
						req = s.Request(id)
					}
					var ids []uint32
					if fast {
						ids = m.MatchFast(req, w)
					} else {
						ids = m.MatchNaive(req, w)
					}
					w.Stats.Requests++
					w.Stats.Bytes += int64(len(req))
					w.Stats.Matches += int64(len(ids))
					if len(ids) > 0 {
						w.Stats.WithMatch++
					}
					from := len(w.out)
					w.out = m.appendResult(w.out, id, ids, w)
					h := maphash.Bytes(hashSeed, w.out[from:]) | 1
					if atomic.SwapUint64(&res.Hashes[k], h) != 0 {
						dups.Add(1)
					}
				}
				if out != nil {
					// w.out is serialized text owned by this worker; it is copied into the
					// shared writer under the lock before the buffer is reused.
					outMu.Lock()
					if _, err := out.Write(w.out); err != nil && writeErr == nil {
						writeErr = err
					}
					outMu.Unlock()
				}
			}
			stats[wi] = w.Stats
		}()
	}
	wg.Wait()
	if out != nil {
		if err := out.Flush(); err != nil && writeErr == nil {
			writeErr = err
		}
	}
	res.Seconds = time.Since(start).Seconds()
	if e := readErr.Load(); e != nil {
		return nil, *e
	}
	if writeErr != nil {
		return nil, fmt.Errorf("writing results: %w", writeErr)
	}
	for _, st := range stats {
		res.Stats.add(st)
	}
	res.Duplicates = dups.Load()
	res.Requests, res.Bytes = res.Stats.Requests, res.Stats.Bytes
	res.Matches, res.WithMatch = res.Stats.Matches, res.Stats.WithMatch
	res.ReqPerSec = float64(res.Requests) / res.Seconds
	res.MBPerSec = float64(res.Bytes) / 1e6 / res.Seconds
	res.RegexCalls = float64(res.Stats.RegexCalls) / float64(max(res.Requests, 1))
	return res, nil
}

// Diff compares two runs over the same sample request by request. It returns the
// positions (indexes into the sample) whose output lines differ, and how many requests
// either run failed to process at all.
func Diff(a, b *Result) (differ []int, missing int) {
	if len(a.Hashes) != len(b.Hashes) {
		return nil, max(len(a.Hashes), len(b.Hashes))
	}
	for k := range a.Hashes {
		switch {
		case a.Hashes[k] == 0 || b.Hashes[k] == 0:
			missing++
		case a.Hashes[k] != b.Hashes[k]:
			differ = append(differ, k)
		}
	}
	return
}
