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
	"strconv"
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
	Mode      string // "fast" or "naive"
	SplitOnly bool   // read and find element boundaries only: no parsing, matching or output
	Parser    string // key of parsers
	Workers   int
	Readers   int // files read and split at the same time, like partitions with one consumer each
	Window    int // a reader may start file f only while f < (first file not yet split) + Window; at least Readers
	// The writer holds the results of a file until every earlier file is split, so at most
	// Window files' results wait at once (~50 bytes per request); QueueBytes does not count them.
	Out        io.Writer
	ChunkSize  int   // bytes read per chunk; a chunk carries every complete element in it
	QueueJobs  int   // chunks waiting for workers
	QueueBytes int64 // JSON bytes queued or being processed
}

type StreamResult struct {
	*Result
	Parser, Backend   string
	Readers           int
	InputBytes        int64 // JSON bytes read
	Files             int
	ReaderWaitSec     float64 // readers blocked by the full queue (backpressure), summed
	ReadStallSec      float64 // read-ahead blocked because splitting was behind, summed
	WorkerIdleSec     float64 // sum over workers of time waiting for a chunk
	SplitSec, ReadSec float64 // summed over readers
	WriterSec         float64 // writer adding ids, hashing and writing
	AllocBytes        uint64
	Allocs            uint64
	NumGC             uint32
	MaxChunk          int
	Parse             ParserStats
	SplitOnly         bool
	// Summed over workers (CPU-ish time inside each stage; the clock reads add ~50 ns per request).
	ParseSec, MatchSec, FormatSec, WriteSec float64
}

// streamJob is a chunk of one file: complete elements, numbered within that file.
type streamJob struct {
	buf   []byte
	spans []span
	file  int
	local int64 // position of the first element within its file
}

// streamOut is what a worker hands to the writer: result lines without their ids.
type streamOut struct {
	file  int
	local int64
	tails []byte  // `,"hard":[...],"soft":[...]}\n` per element, back to back
	ends  []int32 // end of each element's tail
}

var streamSeed = maphash.MakeSeed()

// RunStream processes the JSON files end to end.
//
// Files are the unit of parallel reading, like partitions with one consumer each:
// cfg.Readers goroutines each take the next file, read it in order and cut it into
// chunks of complete elements, numbered within that file. Workers parse and match
// chunks from any file. The writer turns (file, position in file) into the global
// request id once the element counts of all earlier files are known:
//
//	id = (elements in files 0..file-1) + position in file
//
// which is the same id a single reader, or a corpus prepared from the same files, would
// give. A reader stays at most cfg.Window files ahead of the first file not yet split,
// which bounds how long results wait for their file's position.
func RunStream(m *Matcher, paths []string, cfg StreamConfig) (*StreamResult, error) {
	info, ok := parsers[cfg.Parser]
	if !ok {
		return nil, fmt.Errorf("parser %q is not compiled in (have %v)", cfg.Parser, ParserNames())
	}
	if cfg.Workers < 1 {
		cfg.Workers = runtime.NumCPU()
	}
	if cfg.Readers < 1 {
		cfg.Readers = 1
	}
	if cfg.Window <= 0 {
		cfg.Window = 4 * cfg.Readers
	}
	cfg.Window = max(cfg.Window, cfg.Readers)
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
		Parser: cfg.Parser, Backend: info.Backend(), Files: len(paths), Readers: cfg.Readers}
	var ms0 runtime.MemStats
	runtime.ReadMemStats(&ms0)

	var (
		jobs      = make(chan *streamJob, cfg.QueueJobs)
		outs      = make(chan streamOut, cfg.QueueJobs+cfg.Workers)
		filesDone = make(chan [2]int64, len(paths)) // {file, elements}; never blocks
		mu        sync.Mutex
		cond      = sync.NewCond(&mu) // queue byte budget
		inFlight  int64
		claimMu   sync.Mutex
		claimCond = sync.NewCond(&claimMu) // reader window
		failed    atomic.Pointer[error]
		wg, rg    sync.WaitGroup
		stats     = make([]Stats, cfg.Workers)
		idle      = make([]time.Duration, cfg.Workers)
		pstats    = make([]ParserStats, cfg.Workers)
		stage     = make([][4]time.Duration, cfg.Workers) // parse+normalize, match, format, hand-over

		readNs, stallNs, splitNs, waitNs, inputBytes, maxChunk atomic.Int64
	)
	fail := func(err error) {
		failed.CompareAndSwap(nil, &err)
		// Under the locks, so a waiter that has just seen no failure cannot miss this.
		mu.Lock()
		cond.Broadcast()
		mu.Unlock()
		claimMu.Lock()
		claimCond.Broadcast()
		claimMu.Unlock()
	}
	// Buffers circulate through bounded free lists; the GC does not empty them (it
	// does empty a sync.Pool), and a buffer grown for a huge element is not kept.
	freeChunks := make(chan []byte, int(cfg.QueueBytes/int64(cfg.ChunkSize))+cfg.Workers+2*cfg.Readers+2)
	freeBlocks := make(chan []byte, 4*cfg.Readers+2)
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

	// --- writer: ids, hashes, output ---
	var (
		hashes     []uint64
		total      int64
		writerTime time.Duration
	)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		var bw *bufio.Writer
		if cfg.Out != nil {
			bw = bufio.NewWriterSize(cfg.Out, 1<<20)
		}
		count := make([]int64, len(paths))
		known := make([]bool, len(paths))
		base := make([]int64, len(paths)+1) // base[resolved] is always known
		resolved := 0                       // files whose element count is known, in order
		pending := map[int][]streamOut{}
		var line []byte
		emit := func(o streamOut) {
			t := time.Now()
			id, from := base[o.file]+o.local, int32(0)
			for k, end := range o.ends {
				n := id + int64(k)
				line = append(line[:0], `{"id":`...)
				line = strconv.AppendInt(line, n, 10)
				line = append(line, o.tails[from:end]...)
				from = end
				for int64(len(hashes)) <= n {
					hashes = append(hashes, 0)
				}
				if hashes[n] != 0 {
					fail(fmt.Errorf("request id %d produced twice", n))
				}
				hashes[n] = maphash.Bytes(streamSeed, line) | 1
				if bw != nil {
					if _, err := bw.Write(line); err != nil {
						fail(fmt.Errorf("writing results: %w", err))
					}
				}
			}
			writerTime += time.Since(t)
		}
		outsCh, doneCh := outs, filesDone
		for outsCh != nil || doneCh != nil {
			select {
			case o, ok := <-outsCh:
				if !ok {
					outsCh = nil
				} else if o.file <= resolved { // its base is known
					emit(o)
				} else {
					pending[o.file] = append(pending[o.file], o)
				}
			case fd, ok := <-doneCh:
				if !ok {
					doneCh = nil
					continue
				}
				count[fd[0]], known[fd[0]] = fd[1], true
				for resolved < len(paths) && known[resolved] {
					base[resolved+1] = base[resolved] + count[resolved]
					resolved++
					for _, o := range pending[resolved] {
						emit(o)
					}
					delete(pending, resolved)
				}
			}
		}
		if bw != nil {
			if err := bw.Flush(); err != nil {
				fail(fmt.Errorf("writing results: %w", err))
			}
		}
		if len(pending) > 0 {
			fail(errors.New("results left for files whose position never became known"))
		}
		total = base[resolved]
	}()

	// --- workers ---
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
				o := streamOut{file: j.file, local: j.local, tails: make([]byte, 0, 48*len(j.spans)), ends: make([]int32, 0, len(j.spans))}
				for k, sp := range j.spans {
					t0 := time.Now()
					norm, err = p.normalize(j.buf[sp.start:sp.end], norm[:0])
					if err != nil {
						fail(fmt.Errorf("%s, element %d: %w", paths[j.file], j.local+int64(k), err))
						break
					}
					t1 := time.Now()
					var ids []uint32
					if fast {
						ids = m.MatchFast(norm, w)
					} else {
						ids = m.MatchNaive(norm, w)
					}
					t2 := time.Now()
					w.Stats.Requests++
					w.Stats.Bytes += int64(len(norm))
					w.Stats.Matches += int64(len(ids))
					if len(ids) > 0 {
						w.Stats.WithMatch++
					}
					o.tails = m.appendResultTail(o.tails, ids, w)
					o.ends = append(o.ends, int32(len(o.tails)))
					stage[wi][0] += t1.Sub(t0)
					stage[wi][1] += t2.Sub(t1)
					stage[wi][2] += time.Since(t2)
					if cap(norm) > maxKeptBuffer || sp.end-sp.start > maxKeptBuffer {
						norm = make([]byte, 0, 64<<10)
						p.trim()
					}
				}
				n := len(j.spans)
				release(j)
				if failed.Load() == nil && len(o.ends) == n {
					t := time.Now()
					outs <- o
					stage[wi][3] += time.Since(t)
				}
			}
			stats[wi] = w.Stats
			pstats[wi] = p.stats()
		}()
	}

	// --- readers: one file at a time each, read-ahead + splitting ---
	type block struct {
		b   []byte
		eof bool
		err error
	}
	splitFile := func(fi int) (int64, bool) {
		path := paths[fi]
		blocks := make(chan block, 4)
		go func() { // read-ahead for this file
			defer close(blocks)
			f, err := os.Open(path)
			if err != nil {
				blocks <- block{err: err}
				return
			}
			defer f.Close()
			for {
				var b []byte
				select {
				case b = <-freeBlocks:
				default:
					b = make([]byte, cfg.ChunkSize)
				}
				t := time.Now()
				n, err := io.ReadFull(f, b[:cap(b)])
				readNs.Add(int64(time.Since(t)))
				eof := err == io.EOF || err == io.ErrUnexpectedEOF
				if err != nil && !eof {
					blocks <- block{err: err}
					return
				}
				t = time.Now()
				blocks <- block{b: b[:n], eof: eof}
				stallNs.Add(int64(time.Since(t)))
				if eof || failed.Load() != nil {
					return
				}
			}
		}()
		var local int64
		var spans []span
		st := expectOpen
		buf := chunk(cfg.ChunkSize)
		rescanAt := 0 // an unfinished element is rescanned only once the buffer has doubled
		for blk := range blocks {
			if failed.Load() != nil {
				continue // drain so the read-ahead can stop
			}
			if blk.err != nil {
				fail(fmt.Errorf("%s: %w", path, blk.err))
				continue
			}
			if cap(buf)-len(buf)-jsonPadding < len(blk.b) { // an element longer than a chunk
				bigger := make([]byte, len(buf), 2*(len(buf)+len(blk.b))+jsonPadding)
				copy(bigger, buf)
				buf = bigger
			}
			buf = append(buf, blk.b...)
			inputBytes.Add(int64(len(blk.b)))
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
			splitNs.Add(int64(time.Since(t)))
			if err != nil {
				fail(fmt.Errorf("%s: %w", path, err))
				continue
			}
			if len(spans) > 0 {
				// The unfinished tail moves to a fresh chunk before this one is handed over.
				tail := buf[consumed:]
				nb := append(chunk(max(cfg.ChunkSize, 2*len(tail))), tail...)
				j := &streamJob{buf: buf[:consumed], spans: append([]span(nil), spans...), file: fi, local: local}
				local += int64(len(spans))
				for c := maxChunk.Load(); int64(cap(buf)) > c && !maxChunk.CompareAndSwap(c, int64(cap(buf))); c = maxChunk.Load() {
				}
				t = time.Now()
				mu.Lock()
				for inFlight > 0 && inFlight+int64(len(j.buf)) > cfg.QueueBytes && failed.Load() == nil {
					cond.Wait()
				}
				inFlight += int64(len(j.buf))
				mu.Unlock()
				jobs <- j
				waitNs.Add(int64(time.Since(t)))
				buf = nb
				rescanAt = 0
			} else {
				// Drop what the scanner consumed ('[', ',', whitespace); the state remembers it.
				buf = buf[:copy(buf, buf[consumed:])]
				rescanAt = 2 * len(buf)
			}
			if blk.eof && (st != arrayDone || len(bytes.TrimSpace(buf)) > 0) {
				fail(fmt.Errorf("%s: the file ends inside the JSON array", path))
			}
		}
		return local, failed.Load() == nil
	}
	nextFile, firstUndone := 0, 0
	splitDone := make([]bool, len(paths))
	for ri := 0; ri < cfg.Readers; ri++ {
		rg.Add(1)
		go func() {
			defer rg.Done()
			for {
				claimMu.Lock()
				for nextFile < len(paths) && nextFile >= firstUndone+cfg.Window && failed.Load() == nil {
					claimCond.Wait()
				}
				if nextFile >= len(paths) || failed.Load() != nil {
					claimMu.Unlock()
					return
				}
				fi := nextFile
				nextFile++
				claimMu.Unlock()
				n, ok := splitFile(fi)
				if ok {
					filesDone <- [2]int64{int64(fi), n}
				}
				claimMu.Lock()
				splitDone[fi] = true
				for firstUndone < len(paths) && splitDone[firstUndone] {
					firstUndone++
				}
				claimCond.Broadcast()
				claimMu.Unlock()
			}
		}()
	}

	rg.Wait()
	close(filesDone)
	close(jobs)
	wg.Wait()
	close(outs)
	<-writerDone
	res.Seconds = time.Since(start).Seconds()
	if e := failed.Load(); e != nil {
		return nil, *e
	}

	for _, st := range stats {
		res.Stats.add(st)
	}
	res.InputBytes, res.MaxChunk = inputBytes.Load(), int(maxChunk.Load())
	res.ReadSec, res.ReadStallSec = time.Duration(readNs.Load()).Seconds(), time.Duration(stallNs.Load()).Seconds()
	res.SplitSec, res.ReaderWaitSec = time.Duration(splitNs.Load()).Seconds(), time.Duration(waitNs.Load()).Seconds()
	res.WriterSec = writerTime.Seconds()
	res.Requests = res.Stats.Requests
	res.ReqPerSec = float64(res.Requests) / res.Seconds
	res.MBPerSec = float64(res.InputBytes) / 1e6 / res.Seconds
	if cfg.SplitOnly {
		res.SplitOnly = true
		if res.Requests != total {
			return nil, fmt.Errorf("%d elements counted by readers, %d seen by workers", total, res.Requests)
		}
		return res, nil
	}

	// Every id from 0 to total-1 must have been written exactly once.
	if int64(len(hashes)) != total || res.Requests != total {
		return nil, fmt.Errorf("%d results, %d processed, %d elements in the files", len(hashes), res.Requests, total)
	}
	for id, h := range hashes {
		if h == 0 {
			return nil, fmt.Errorf("request id %d was not processed", id)
		}
	}
	res.Hashes = hashes
	for _, d := range idle {
		res.WorkerIdleSec += d.Seconds()
	}
	for _, st := range stage {
		res.ParseSec += st[0].Seconds()
		res.MatchSec += st[1].Seconds()
		res.FormatSec += st[2].Seconds()
		res.WriteSec += st[3].Seconds()
	}
	for _, ps := range pstats {
		res.Parse.add(ps)
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	res.AllocBytes, res.Allocs, res.NumGC = ms.TotalAlloc-ms0.TotalAlloc, ms.Mallocs-ms0.Mallocs, ms.NumGC-ms0.NumGC
	res.Inconclusive = Inconclusive() - res.Inconclusive0
	res.Bytes = res.Stats.Bytes
	res.Matches, res.WithMatch = res.Stats.Matches, res.Stats.WithMatch
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
