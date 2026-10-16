package matcher

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-faster/jx"
)

// End-to-end streaming mode: every run reads the source JSON files again.
//
//	read file chunk → find element boundaries → bounded queue → N workers:
//	    parse the element (jx or simdjson) → normalize → prefilter → regex → output
//
// The source files are single-line JSON arrays of objects, not JSONL, so element
// boundaries are found by a small scanner that only tracks strings (with backslash
// escapes) and nesting depth. It does not validate the element: the parser does, and
// a malformed element or array is an error, never an empty request.

// msgParser parses one JSON object and appends the normalized request to dst. msg has
// at least jsonPadding readable bytes of capacity after its end (simdjson reads ahead).
// Each worker owns one parser.
type msgParser interface {
	normalize(msg, dst []byte) ([]byte, error)
	// trim drops buffers that grew past the normal size, so that one huge message does
	// not stay allocated for the rest of the run.
	trim()
	stats() ParserStats
}

// ParserStats says which backend actually parsed the messages. A SIMD parser that
// silently handed everything to its fallback would show up here.
type ParserStats struct {
	Primary      string           `json:"primary"`       // backend meant to parse every message
	PrimaryMsgs  int64            `json:"primary_msgs"`  // messages it parsed
	FallbackMsgs int64            `json:"fallback_msgs"` // messages it refused, parsed by jx
	Reasons      map[string]int64 `json:"fallback_reasons,omitempty"`
	// Buffers the C++ side grew (simdjson's parser, the header string). Go's allocation
	// statistics, and therefore -benchmem, do not see C/C++ heap allocations at all.
	NativeGrowths     int64 `json:"native_growths"`
	NativeGrowthBytes int64 `json:"native_growth_bytes"`
}

func (s *ParserStats) add(o ParserStats) {
	if s.Primary == "" {
		s.Primary = o.Primary
	}
	s.PrimaryMsgs += o.PrimaryMsgs
	s.FallbackMsgs += o.FallbackMsgs
	s.NativeGrowths += o.NativeGrowths
	s.NativeGrowthBytes += o.NativeGrowthBytes
	for k, v := range o.Reasons {
		if s.Reasons == nil {
			s.Reasons = map[string]int64{}
		}
		s.Reasons[k] += v
	}
}

const jsonPadding = 64

type parserInfo struct {
	New     func() (msgParser, error)
	Backend func() string // what actually runs, reported with the results
}

var parsers = map[string]parserInfo{
	"jx": {New: func() (msgParser, error) { return newJxParser(), nil }, Backend: func() string { return "go (no SIMD)" }},
}

func ParserNames() []string {
	var n []string
	for k := range parsers {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func ParserBackend(name string) string {
	if p, ok := parsers[name]; ok {
		return p.Backend()
	}
	return ""
}

type jxParser struct {
	d    *jx.Decoder
	obj  *jxObject
	msgs int64
}

func newJxParser() *jxParser { return &jxParser{d: jx.DecodeBytes(nil), obj: newJxObject()} }

func (p *jxParser) stats() ParserStats { return ParserStats{Primary: "jx", PrimaryMsgs: p.msgs} }

func (p *jxParser) normalize(msg, dst []byte) ([]byte, error) {
	p.msgs++
	p.d.ResetBytes(msg)
	if p.d.Next() != jx.Object {
		return dst, errors.New("array element is not a JSON object")
	}
	return p.obj.decode(p.d, dst)
}

func (p *jxParser) trim() {
	if cap(p.obj.body) > maxKeptBuffer {
		p.obj = newJxObject()
	}
}

// maxKeptBuffer: a worker keeps buffers up to this size between messages.
const maxKeptBuffer = 8 << 20

// --- element boundaries -------------------------------------------------------------

type arrayState uint8

const (
	expectOpen    arrayState = iota // before '['
	expectFirst                     // after '[': element or ']'
	expectElement                   // after ',': element
	expectComma                     // after an element: ',' or ']'
	arrayDone                       // after ']': only whitespace
)

type span struct{ start, end int }

// splitElements finds the complete array elements in b, continuing from state *st. It
// returns them and how many bytes were consumed; an element cut off by the end of b is
// left unconsumed for the next call.
func splitElements(b []byte, st *arrayState, spans []span) ([]span, int, error) {
	i := 0
	for i < len(b) {
		c := b[i]
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			i++
			continue
		}
		switch *st {
		case expectOpen:
			if c != '[' {
				return spans, i, fmt.Errorf("expected '[' at the start of the file, got %q", c)
			}
			*st = expectFirst
			i++
		case expectFirst, expectElement:
			if c == ']' && *st == expectFirst {
				*st = arrayDone
				i++
				continue
			}
			if c != '{' {
				return spans, i, fmt.Errorf("array element is not an object (starts with %q)", c)
			}
			end := objectEnd(b, i)
			if end < 0 {
				return spans, i, nil // incomplete: wait for more data
			}
			spans = append(spans, span{i, end})
			*st = expectComma
			i = end
		case expectComma:
			switch c {
			case ',':
				*st = expectElement
			case ']':
				*st = arrayDone
			default:
				return spans, i, fmt.Errorf("expected ',' or ']' after an element, got %q", c)
			}
			i++
		case arrayDone:
			return spans, i, fmt.Errorf("data after the end of the array: %q", c)
		}
	}
	return spans, i, nil
}

// objectEnd returns the index after the '}' closing the object that starts at b[i],
// or -1 if b ends first. Strings are skipped with bytes.IndexByte, which is vectorized
// on arm64 and amd64; most bytes of a request are inside strings.
func objectEnd(b []byte, i int) int {
	depth := 0
	for i < len(b) {
		switch b[i] {
		case '"':
			start := i + 1
			j := start
			for {
				k := bytes.IndexByte(b[j:], '"')
				if k < 0 {
					return -1
				}
				q := j + k
				n := 0
				for p := q - 1; p >= start && b[p] == '\\'; p-- {
					n++
				}
				if n%2 == 0 { // not escaped
					i = q + 1
					break
				}
				j = q + 1
			}
			continue
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return -1
}

// --- pipeline -----------------------------------------------------------------------

type StreamConfig struct {
	Mode       string // "fast" or "naive"
	SplitOnly  bool   // read and find element boundaries only: no parsing, matching or output
	Parser     string // key of parsers
	Workers    int
	Out        io.Writer
	ChunkSize  int   // bytes read per chunk; a chunk carries every complete element in it
	QueueJobs  int   // chunks waiting for workers
	QueueBytes int64 // JSON bytes queued or being processed
}

type StreamResult struct {
	*Result
	Parser, Backend   string
	InputBytes        int64 // JSON bytes read
	Files             int
	ReaderWaitSec     float64 // splitter blocked by the full queue (backpressure)
	ReadStallSec      float64 // file reader blocked because the splitter was behind
	WorkerIdleSec     float64 // sum over workers of time waiting for a chunk
	SplitSec, ReadSec float64
	AllocBytes        uint64
	Allocs            uint64
	NumGC             uint32
	MaxChunk          int
	Parse             ParserStats
	SplitOnly         bool
}

type streamJob struct {
	buf    []byte
	spans  []span
	first  int64
	file   int
	hashes []uint64
}

var streamSeed = maphash.MakeSeed()

// RunStream processes the JSON files end to end. Request ids are assigned in file
// order and element order, so they equal the ids of a corpus prepared from the same
// files. The timed region starts before the first file is opened.
func RunStream(m *Matcher, paths []string, cfg StreamConfig) (*StreamResult, error) {
	info, ok := parsers[cfg.Parser]
	if !ok {
		return nil, fmt.Errorf("parser %q is not compiled in (have %v)", cfg.Parser, ParserNames())
	}
	if cfg.Workers < 1 {
		cfg.Workers = runtime.NumCPU()
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = 1 << 20
	}
	if cfg.QueueJobs <= 0 {
		cfg.QueueJobs = 2 * cfg.Workers
	}
	if cfg.QueueBytes <= 0 {
		cfg.QueueBytes = 256 << 20
	}
	fast := cfg.Mode != "naive"
	old := runtime.GOMAXPROCS(cfg.Workers)
	defer runtime.GOMAXPROCS(old)

	res := &StreamResult{Result: &Result{Engine: m.Rules.Label(), Mode: cfg.Mode, Workers: cfg.Workers, Access: "stream", GOMAXPROCS: cfg.Workers, Inconclusive0: Inconclusive()},
		Parser: cfg.Parser, Backend: info.Backend(), Files: len(paths)}
	var ms0 runtime.MemStats
	runtime.ReadMemStats(&ms0)

	var (
		jobs     = make(chan *streamJob, cfg.QueueJobs)
		done     = make(chan *streamJob, cfg.QueueJobs+cfg.Workers)
		mu       sync.Mutex
		cond     = sync.NewCond(&mu)
		inFlight int64
		failed   atomic.Pointer[error]
		outMu    sync.Mutex
		out      *bufio.Writer
		wg       sync.WaitGroup
		stats    = make([]Stats, cfg.Workers)
		idle     = make([]time.Duration, cfg.Workers)
		pstats   = make([]ParserStats, cfg.Workers)
	)
	fail := func(err error) { failed.CompareAndSwap(nil, &err); cond.Broadcast() }
	if cfg.Out != nil {
		out = bufio.NewWriterSize(cfg.Out, 1<<20)
	}
	// Buffers circulate through bounded free lists; the GC does not empty them (it
	// does empty a sync.Pool), and a buffer grown for a huge element is not kept.
	// As many as can be in flight at once: the queue's byte budget in chunks, plus one
	// per worker and a few for the splitter.
	freeChunks := make(chan []byte, int(cfg.QueueBytes/int64(cfg.ChunkSize))+cfg.Workers+4)
	chunk := func(min int) []byte {
		select {
		case b := <-freeChunks:
			if cap(b) >= min+jsonPadding {
				return b[:0]
			}
		default:
		}
		return make([]byte, 0, max(min, 2*cfg.ChunkSize)+jsonPadding)
	}
	release := func(j *streamJob) {
		mu.Lock()
		inFlight -= int64(len(j.buf))
		cond.Broadcast()
		mu.Unlock()
		if cap(j.buf) <= maxKeptBuffer {
			select {
			case freeChunks <- j.buf[:0]:
			default:
			}
		}
		j.buf = nil
	}

	start := time.Now()
	for wi := 0; wi < cfg.Workers; wi++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := info.New()
			if err != nil {
				fail(err)
				for j := range jobs {
					release(j)
				}
				return
			}
			w := m.NewWorker()
			norm := make([]byte, 0, 64<<10)
			for {
				t := time.Now()
				j, ok := <-jobs
				idle[wi] += time.Since(t)
				if !ok {
					break
				}
				if failed.Load() != nil {
					release(j)
					continue
				}
				if cfg.SplitOnly { // measures reading and boundary finding alone
					w.Stats.Requests += int64(len(j.spans))
					release(j)
					continue
				}
				j.hashes = make([]uint64, len(j.spans))
				w.out = w.out[:0]
				for k, sp := range j.spans {
					id := j.first + int64(k)
					norm, err = p.normalize(j.buf[sp.start:sp.end], norm[:0])
					if err != nil {
						fail(fmt.Errorf("%s, element %d (request id %d): %w", paths[j.file], k, id, err))
						break
					}
					var ids []uint32
					if fast {
						ids = m.MatchFast(norm, w)
					} else {
						ids = m.MatchNaive(norm, w)
					}
					w.Stats.Requests++
					w.Stats.Bytes += int64(len(norm))
					w.Stats.Matches += int64(len(ids))
					if len(ids) > 0 {
						w.Stats.WithMatch++
					}
					from := len(w.out)
					w.out = m.appendResult(w.out, int(id), ids, w)
					j.hashes[k] = maphash.Bytes(streamSeed, w.out[from:]) | 1
					if cap(norm) > maxKeptBuffer || sp.end-sp.start > maxKeptBuffer {
						norm = make([]byte, 0, 64<<10)
						p.trim()
					}
				}
				if out != nil && failed.Load() == nil {
					outMu.Lock()
					if _, err := out.Write(w.out); err != nil {
						fail(fmt.Errorf("writing results: %w", err))
					}
					outMu.Unlock()
				}
				if cap(w.out) > maxKeptBuffer {
					w.out = nil
				}
				release(j)
				done <- j
			}
			stats[wi] = w.Stats
			pstats[wi] = p.stats()
		}()
	}

	// Collector: hashes per chunk, assembled by id once everything is done.
	var collected []*streamJob
	collectDone := make(chan struct{})
	go func() {
		for j := range done {
			collected = append(collected, j)
		}
		close(collectDone)
	}()

	// Reading and splitting overlap: one goroutine reads the files in order into raw
	// blocks, this goroutine appends them to the current chunk, finds the complete
	// elements and hands them out. Files are read in order, so ids are assigned in order.
	type block struct {
		b    []byte
		file int
		eof  bool
		err  error
	}
	blocks := make(chan block, 4)
	freeBlocks := make(chan []byte, 6)
	var readDur, readStall time.Duration
	go func() {
		defer close(blocks)
		for fi, path := range paths {
			f, err := os.Open(path)
			if err != nil {
				blocks <- block{file: fi, err: err}
				return
			}
			for {
				var b []byte
				select {
				case b = <-freeBlocks:
				default:
					b = make([]byte, cfg.ChunkSize)
				}
				t := time.Now()
				n, err := io.ReadFull(f, b[:cap(b)])
				readDur += time.Since(t)
				eof := err == io.EOF || err == io.ErrUnexpectedEOF
				if err != nil && !eof {
					blocks <- block{file: fi, err: err}
					f.Close()
					return
				}
				t = time.Now()
				blocks <- block{b: b[:n], file: fi, eof: eof}
				readStall += time.Since(t)
				if eof || failed.Load() != nil {
					break
				}
			}
			f.Close()
			if failed.Load() != nil {
				return
			}
		}
	}()

	var next int64
	var splitDur, waitDur time.Duration
	var spans []span
	st := expectOpen
	buf := chunk(cfg.ChunkSize)
	rescanAt := 0 // an unfinished element is rescanned only once the buffer has doubled
	for blk := range blocks {
		if failed.Load() != nil {
			continue // drain so the reader can stop
		}
		if blk.err != nil {
			fail(fmt.Errorf("%s: %w", paths[blk.file], blk.err))
			continue
		}
		if cap(buf)-len(buf)-jsonPadding < len(blk.b) { // an element longer than a chunk
			bigger := make([]byte, len(buf), 2*(len(buf)+len(blk.b))+jsonPadding)
			copy(bigger, buf)
			buf = bigger
		}
		buf = append(buf, blk.b...)
		res.InputBytes += int64(len(blk.b))
		select {
		case freeBlocks <- blk.b[:0]:
		default:
		}
		if len(buf) < rescanAt && !blk.eof {
			continue // still inside one large element; scanning it again now would be O(n^2)
		}
		t := time.Now()
		var consumed int
		var err error
		spans, consumed, err = splitElements(buf, &st, spans[:0])
		splitDur += time.Since(t)
		if err != nil {
			fail(fmt.Errorf("%s: %w", paths[blk.file], err))
			continue
		}
		if len(spans) > 0 {
			// The unfinished tail moves to a fresh chunk before this one is handed over.
			tail := buf[consumed:]
			nb := append(chunk(max(cfg.ChunkSize, 2*len(tail))), tail...)
			j := &streamJob{buf: buf[:consumed], spans: append([]span(nil), spans...), first: next, file: blk.file}
			next += int64(len(spans))
			res.MaxChunk = max(res.MaxChunk, cap(buf))
			t = time.Now()
			mu.Lock()
			for inFlight > 0 && inFlight+int64(len(j.buf)) > cfg.QueueBytes && failed.Load() == nil {
				cond.Wait()
			}
			inFlight += int64(len(j.buf))
			mu.Unlock()
			jobs <- j
			waitDur += time.Since(t)
			buf = nb
			rescanAt = 0
		} else {
			// Drop what the scanner consumed ('[', ',', whitespace); the state remembers it.
			buf = buf[:copy(buf, buf[consumed:])]
			rescanAt = 2 * len(buf)
		}
		if blk.eof {
			if st != arrayDone || len(bytes.TrimSpace(buf)) > 0 {
				fail(fmt.Errorf("%s: the file ends inside the JSON array", paths[blk.file]))
				continue
			}
			st, buf, rescanAt = expectOpen, buf[:0], 0
		}
	}
	close(jobs)
	wg.Wait()
	close(done)
	<-collectDone
	if out != nil {
		if err := out.Flush(); err != nil {
			fail(fmt.Errorf("writing results: %w", err))
		}
	}
	res.Seconds = time.Since(start).Seconds()
	if e := failed.Load(); e != nil {
		return nil, *e
	}

	if cfg.SplitOnly {
		collected = nil
		next = 0
		for _, st := range stats {
			res.Stats.add(st)
		}
		res.Requests = res.Stats.Requests
		res.ReqPerSec = float64(res.Requests) / res.Seconds
		res.MBPerSec = float64(res.InputBytes) / 1e6 / res.Seconds
		res.ReaderWaitSec, res.ReadSec, res.SplitSec, res.ReadStallSec = waitDur.Seconds(), readDur.Seconds(), splitDur.Seconds(), readStall.Seconds()
		res.SplitOnly = true
		return res, nil
	}
	// Every id from 0 to next-1 must have been processed exactly once.
	sort.Slice(collected, func(a, b int) bool { return collected[a].first < collected[b].first })
	res.Hashes = make([]uint64, 0, next)
	for _, j := range collected {
		if int64(len(res.Hashes)) != j.first {
			return nil, fmt.Errorf("request ids %d..%d missing or duplicated", len(res.Hashes), j.first)
		}
		res.Hashes = append(res.Hashes, j.hashes...)
	}
	if int64(len(res.Hashes)) != next {
		return nil, fmt.Errorf("%d results for %d requests", len(res.Hashes), next)
	}
	for _, st := range stats {
		res.Stats.add(st)
	}
	for _, d := range idle {
		res.WorkerIdleSec += d.Seconds()
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	res.AllocBytes, res.Allocs, res.NumGC = ms.TotalAlloc-ms0.TotalAlloc, ms.Mallocs-ms0.Mallocs, ms.NumGC-ms0.NumGC
	res.ReaderWaitSec, res.ReadSec, res.SplitSec = waitDur.Seconds(), readDur.Seconds(), splitDur.Seconds()
	res.ReadStallSec = readStall.Seconds()
	res.Inconclusive = Inconclusive() - res.Inconclusive0
	for _, ps := range pstats {
		res.Parse.add(ps)
	}
	res.Requests, res.Bytes = res.Stats.Requests, res.Stats.Bytes
	res.Matches, res.WithMatch = res.Stats.Matches, res.Stats.WithMatch
	res.ReqPerSec = float64(res.Requests) / res.Seconds
	res.MBPerSec = float64(res.InputBytes) / 1e6 / res.Seconds
	res.RegexCalls = float64(res.Stats.RegexCalls) / float64(max(res.Requests, 1))
	return res, nil
}

// StreamNormalized feeds every element through parser p and calls fn with its id and
// normalized bytes, without matching. Used to check that a parser produces exactly the
// bytes of the prepared corpus. Single-threaded.
func StreamNormalized(paths []string, parser string, fn func(id int64, norm []byte) error) error {
	info, ok := parsers[parser]
	if !ok {
		return fmt.Errorf("parser %q is not compiled in", parser)
	}
	p, err := info.New()
	if err != nil {
		return err
	}
	var id int64
	var spans []span
	norm := []byte{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		padded := make([]byte, len(data), len(data)+jsonPadding)
		copy(padded, data)
		st := expectOpen
		spans, consumed, err := splitElements(padded, &st, spans[:0])
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if st != arrayDone || len(bytes.TrimSpace(padded[consumed:])) > 0 {
			return fmt.Errorf("%s: the file ends inside the JSON array", path)
		}
		for k, sp := range spans {
			if norm, err = p.normalize(padded[sp.start:sp.end], norm[:0]); err != nil {
				return fmt.Errorf("%s, element %d: %w", path, k, err)
			}
			if err := fn(id, norm); err != nil {
				return err
			}
			id++
		}
		p.trim()
	}
	return nil
}
