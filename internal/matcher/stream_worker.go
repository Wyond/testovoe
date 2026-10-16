package matcher

import (
	"fmt"
	"time"
)

// streamWorker takes chunks from the queue and, for each element, parses and
// normalizes it, matches it and formats its result line without the id. It owns its
// parser, its matcher state and its normalization buffer; a chunk's buffer is its own
// from receiving the job until release.
type streamWorker struct {
	m         *Matcher
	newParser func() (msgParser, error)
	fast      bool
	splitOnly bool
	paths     []string // for error messages

	stats Stats
	parse ParserStats
	idle  time.Duration    // waiting for a chunk
	stage [4]time.Duration // parse+normalize, match, format, hand-over
}

func (sw *streamWorker) run(q *jobQueue, outs chan<- streamOut, fail *failure) {
	p, err := sw.newParser()
	if err != nil {
		fail.set(err)
		for j := range q.jobs {
			q.release(j)
		}
		return
	}
	w := sw.m.NewWorker()
	norm := make([]byte, 0, 64<<10)
	for {
		t := time.Now()
		j, ok := <-q.jobs
		sw.idle += time.Since(t)
		if !ok {
			break
		}
		if fail.failed() {
			q.release(j)
			continue
		}
		if sw.splitOnly { // measures reading and boundary finding alone
			w.Stats.Requests += int64(len(j.spans))
			q.release(j)
			continue
		}
		var o streamOut
		o, norm, err = sw.process(j, p, w, norm)
		if err != nil {
			fail.set(err)
		}
		q.release(j)
		if err == nil && !fail.failed() {
			t := time.Now()
			outs <- o
			sw.stage[3] += time.Since(t)
		}
	}
	sw.stats = w.Stats
	sw.parse = p.stats()
}

// process handles every element of j and returns their result tails, in order.
func (sw *streamWorker) process(j *streamJob, p msgParser, w *Worker, norm []byte) (streamOut, []byte, error) {
	o := streamOut{file: j.file, local: j.local, tails: make([]byte, 0, 48*len(j.spans)), ends: make([]int32, 0, len(j.spans))}
	for k, sp := range j.spans {
		t0 := time.Now()
		var err error
		norm, err = p.normalize(j.buf[sp.start:sp.end], norm[:0])
		if err != nil {
			return o, norm, fmt.Errorf("%s, element %d: %w", sw.paths[j.file], j.local+int64(k), err)
		}
		t1 := time.Now()
		var ids []uint32
		if sw.fast {
			ids = sw.m.MatchFast(norm, w)
		} else {
			ids = sw.m.MatchNaive(norm, w)
		}
		t2 := time.Now()
		w.Stats.Requests++
		w.Stats.Bytes += int64(len(norm))
		w.Stats.Matches += int64(len(ids))
		if len(ids) > 0 {
			w.Stats.WithMatch++
		}
		o.tails = sw.m.appendResultTail(o.tails, ids, w)
		o.ends = append(o.ends, int32(len(o.tails)))
		sw.stage[0] += t1.Sub(t0)
		sw.stage[1] += t2.Sub(t1)
		sw.stage[2] += time.Since(t2)
		if cap(norm) > maxKeptBuffer || sp.end-sp.start > maxKeptBuffer {
			norm = make([]byte, 0, 64<<10)
			p.trim()
		}
	}
	return o, norm, nil
}
