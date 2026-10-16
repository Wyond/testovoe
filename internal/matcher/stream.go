package matcher

import (
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// End-to-end streaming mode: every run reads the source JSON files again.
//
//	K readers (stream_reader.go): file → chunks of complete elements (splitter.go)
//	→ bounded queue (stream_queue.go)
//	→ N workers (stream_worker.go): parse (parser*.go) → normalize → prefilter → regex
//	→ one writer (stream_writer.go): global id, hash, output
//
// Ownership: a chunk buffer is the reader's until it is put into the queue, then the
// receiving worker's until it releases it; results reach the writer by value. Shared
// state is limited to the queue, the file claims and the failure below.

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

// failure keeps the first error of a run. Setting it wakes every goroutine waiting on
// one of conds, under that condition's lock, so a waiter that has just seen no failure
// cannot miss the wake-up. conds are registered before any goroutine starts.
type failure struct {
	err   atomic.Pointer[error]
	conds []*sync.Cond
}

func (f *failure) set(err error) {
	f.err.CompareAndSwap(nil, &err)
	for _, c := range f.conds {
		c.L.Lock()
		c.Broadcast()
		c.L.Unlock()
	}
}

func (f *failure) failed() bool { return f.err.Load() != nil }

// RunStream processes the JSON files end to end.
//
// Files are the unit of parallel reading, like partitions with one consumer each:
// cfg.Readers goroutines each take the next file, read it in order and cut it into
// chunks of complete elements, numbered within that file. Workers parse and match
// chunks from any file. The writer turns (file, position in file) into the global
// request id, which is the same id a single reader, or a corpus prepared from the same
// files, would give. A reader stays at most cfg.Window files ahead of the first file
// not yet split, which bounds how long results wait for their file's position.
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
	old := runtime.GOMAXPROCS(cfg.Workers)
	defer runtime.GOMAXPROCS(old)

	res := &StreamResult{Result: &Result{Engine: m.Rules.Label(), Mode: cfg.Mode, Workers: cfg.Workers, Access: "stream", GOMAXPROCS: cfg.Workers, Inconclusive0: Inconclusive()},
		Parser: cfg.Parser, Backend: info.Backend(), Files: len(paths), Readers: cfg.Readers}
	var ms0 runtime.MemStats
	runtime.ReadMemStats(&ms0)

	fail := &failure{}
	q := newJobQueue(cfg, fail)
	claims := newFileClaims(len(paths), cfg.Window, fail)
	outs := make(chan streamOut, cfg.QueueJobs+cfg.Workers)
	counts := make(chan fileCount, len(paths)) // one per file: never blocks
	reader := &fileReader{q: q, fail: fail, chunkSize: cfg.ChunkSize, freeBlocks: make(chan []byte, 4*cfg.Readers+2)}
	writer := newIDWriter(len(paths), cfg.Out, fail)

	start := time.Now()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		writer.run(outs, counts)
	}()
	workers := make([]*streamWorker, cfg.Workers)
	var wg, rg sync.WaitGroup
	for wi := range workers {
		sw := &streamWorker{m: m, newParser: info.New, fast: cfg.Mode != "naive", splitOnly: cfg.SplitOnly, paths: paths}
		workers[wi] = sw
		wg.Add(1)
		go func() {
			defer wg.Done()
			sw.run(q, outs, fail)
		}()
	}
	for range cfg.Readers {
		rg.Add(1)
		go func() {
			defer rg.Done()
			reader.run(paths, claims, counts)
		}()
	}

	// Shutdown in pipeline order: readers, then workers, then the writer.
	rg.Wait()
	close(counts)
	close(q.jobs)
	wg.Wait()
	close(outs)
	<-writerDone
	res.Seconds = time.Since(start).Seconds()
	if e := fail.err.Load(); e != nil {
		return nil, *e
	}

	for _, sw := range workers {
		res.Stats.add(sw.stats)
	}
	total := writer.total()
	res.InputBytes, res.MaxChunk = reader.inputBytes.Load(), int(q.maxChunk.Load())
	res.ReadSec, res.ReadStallSec = time.Duration(reader.readNs.Load()).Seconds(), time.Duration(reader.stallNs.Load()).Seconds()
	res.SplitSec, res.ReaderWaitSec = time.Duration(reader.splitNs.Load()).Seconds(), time.Duration(q.waitNs.Load()).Seconds()
	res.WriterSec = writer.elapsed.Seconds()
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
	hashes := writer.hashes
	if int64(len(hashes)) != total || res.Requests != total {
		return nil, fmt.Errorf("%d results, %d processed, %d elements in the files", len(hashes), res.Requests, total)
	}
	for id, h := range hashes {
		if h == 0 {
			return nil, fmt.Errorf("request id %d was not processed", id)
		}
	}
	res.Hashes = hashes
	for _, sw := range workers {
		res.WorkerIdleSec += sw.idle.Seconds()
		res.ParseSec += sw.stage[0].Seconds()
		res.MatchSec += sw.stage[1].Seconds()
		res.FormatSec += sw.stage[2].Seconds()
		res.WriteSec += sw.stage[3].Seconds()
		res.Parse.add(sw.parse)
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
