package matcher

import (
	"bufio"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"strconv"
	"time"
)

// streamOut is what a worker hands to the writer: result lines without their ids.
type streamOut struct {
	file  int
	local int64
	tails []byte  // `,"hard":[...],"soft":[...]}\n` per element, back to back
	ends  []int32 // end of each element's tail
}

var streamSeed = maphash.MakeSeed()

// idWriter is the only goroutine that writes results. It turns (file, position in
// file) into the global request id once the element counts of all earlier files are
// known:
//
//	id = (elements in files 0..file-1) + position in file
//
// Results of a file whose base is not known yet wait in pending. Every id gets a hash
// of its line; an id produced twice is an error.
type idWriter struct {
	out      *bufio.Writer // nil: format and hash, do not write
	count    []int64       // elements per file, once known
	known    []bool
	base     []int64 // base[resolved] is always known
	resolved int     // files whose element count is known, in order
	pending  map[int][]streamOut
	line     []byte
	hashes   []uint64 // per id, 0 = not written
	elapsed  time.Duration
	fail     *failure
}

func newIDWriter(files int, out io.Writer, fail *failure) *idWriter {
	w := &idWriter{count: make([]int64, files), known: make([]bool, files), base: make([]int64, files+1),
		pending: map[int][]streamOut{}, fail: fail}
	if out != nil {
		w.out = bufio.NewWriterSize(out, 1<<20)
	}
	return w
}

// run consumes results and file counts until both channels are closed.
func (w *idWriter) run(outs <-chan streamOut, counts <-chan fileCount) {
	for outs != nil || counts != nil {
		select {
		case o, ok := <-outs:
			if !ok {
				outs = nil
			} else if o.file <= w.resolved { // its base is known
				w.emit(o)
			} else {
				w.pending[o.file] = append(w.pending[o.file], o)
			}
		case fc, ok := <-counts:
			if !ok {
				counts = nil
				continue
			}
			w.count[fc.file], w.known[fc.file] = fc.n, true
			for w.resolved < len(w.count) && w.known[w.resolved] {
				w.base[w.resolved+1] = w.base[w.resolved] + w.count[w.resolved]
				w.resolved++
				for _, o := range w.pending[w.resolved] {
					w.emit(o)
				}
				delete(w.pending, w.resolved)
			}
		}
	}
	if w.out != nil {
		if err := w.out.Flush(); err != nil {
			w.fail.set(fmt.Errorf("writing results: %w", err))
		}
	}
	if len(w.pending) > 0 {
		w.fail.set(errors.New("results left for files whose position never became known"))
	}
}

func (w *idWriter) emit(o streamOut) {
	t := time.Now()
	id, from := w.base[o.file]+o.local, int32(0)
	for k, end := range o.ends {
		n := id + int64(k)
		w.line = append(w.line[:0], `{"id":`...)
		w.line = strconv.AppendInt(w.line, n, 10)
		w.line = append(w.line, o.tails[from:end]...)
		from = end
		for int64(len(w.hashes)) <= n {
			w.hashes = append(w.hashes, 0)
		}
		if w.hashes[n] != 0 {
			w.fail.set(fmt.Errorf("request id %d produced twice", n))
		}
		w.hashes[n] = maphash.Bytes(streamSeed, w.line) | 1
		if w.out != nil {
			if _, err := w.out.Write(w.line); err != nil {
				w.fail.set(fmt.Errorf("writing results: %w", err))
			}
		}
	}
	w.elapsed += time.Since(t)
}

// total is the number of elements in the files whose counts are all known.
func (w *idWriter) total() int64 { return w.base[w.resolved] }
