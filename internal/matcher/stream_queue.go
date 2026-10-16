package matcher

import (
	"sync"
	"sync/atomic"
	"time"
)

// streamJob is a chunk of one file: complete elements, numbered within that file.
// Its buffer belongs to the reader until put, then to the worker that receives the job,
// which hands it back with release.
type streamJob struct {
	buf   []byte
	spans []span
	file  int
	local int64 // position of the first element within its file
}

// jobQueue carries chunks from readers to workers. It is bounded twice: by the number
// of chunks in the channel and by the JSON bytes put and not yet released; a reader
// waits in put while the byte budget is used up (backpressure).
//
// Chunk buffers circulate through a bounded free list; the GC does not empty it (it
// does empty a sync.Pool), and a buffer grown for a huge element is not kept.
type jobQueue struct {
	jobs      chan *streamJob
	mu        sync.Mutex
	cond      *sync.Cond
	inFlight  int64 // bytes of chunks put and not yet released
	maxBytes  int64
	chunkSize int
	free      chan []byte
	fail      *failure

	waitNs   atomic.Int64 // readers blocked in put, summed
	maxChunk atomic.Int64 // largest chunk buffer handed over
}

func newJobQueue(cfg StreamConfig, fail *failure) *jobQueue {
	q := &jobQueue{
		jobs:      make(chan *streamJob, cfg.QueueJobs),
		maxBytes:  cfg.QueueBytes,
		chunkSize: cfg.ChunkSize,
		free:      make(chan []byte, int(cfg.QueueBytes/int64(cfg.ChunkSize))+cfg.Workers+2*cfg.Readers+2),
		fail:      fail,
	}
	q.cond = sync.NewCond(&q.mu)
	fail.conds = append(fail.conds, q.cond)
	return q
}

// buffer returns an empty chunk buffer with room for min bytes plus the parser padding.
func (q *jobQueue) buffer(min int) []byte {
	select {
	case b := <-q.free:
		if cap(b) >= min+jsonPadding {
			return b[:0]
		}
	default:
	}
	return make([]byte, 0, max(min, 2*q.chunkSize)+jsonPadding)
}

// put hands j to the workers, waiting while the byte budget is used up. The first chunk
// always passes, so an element larger than the budget cannot deadlock the run.
func (q *jobQueue) put(j *streamJob) {
	for c := q.maxChunk.Load(); int64(cap(j.buf)) > c && !q.maxChunk.CompareAndSwap(c, int64(cap(j.buf))); c = q.maxChunk.Load() {
	}
	t := time.Now()
	q.mu.Lock()
	for q.inFlight > 0 && q.inFlight+int64(len(j.buf)) > q.maxBytes && !q.fail.failed() {
		q.cond.Wait()
	}
	q.inFlight += int64(len(j.buf))
	q.mu.Unlock()
	q.jobs <- j
	q.waitNs.Add(int64(time.Since(t)))
}

// release returns j's bytes to the budget and its buffer to the free list. The caller
// must not touch j.buf afterwards.
func (q *jobQueue) release(j *streamJob) {
	q.mu.Lock()
	q.inFlight -= int64(len(j.buf))
	q.cond.Broadcast()
	q.mu.Unlock()
	if cap(j.buf) <= maxKeptBuffer {
		select {
		case q.free <- j.buf[:0]:
		default:
		}
	}
	j.buf = nil
}
