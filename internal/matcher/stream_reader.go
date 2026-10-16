package matcher

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// fileCount reports that a file has been split completely into n elements.
type fileCount struct {
	file int
	n    int64
}

// fileClaims hands out files in order, one reader per file, and keeps every reader
// within window files of the first file not yet split. The window bounds how many
// files' results wait in the writer for their position.
type fileClaims struct {
	mu          sync.Mutex
	cond        *sync.Cond
	next        int // next file to hand out
	firstUndone int // first file not yet split
	done        []bool
	window      int
	fail        *failure
}

func newFileClaims(files, window int, fail *failure) *fileClaims {
	c := &fileClaims{done: make([]bool, files), window: window, fail: fail}
	c.cond = sync.NewCond(&c.mu)
	fail.conds = append(fail.conds, c.cond)
	return c
}

// claim returns the next file to read; false when there is none or the run failed.
func (c *fileClaims) claim() (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.next < len(c.done) && c.next >= c.firstUndone+c.window && !c.fail.failed() {
		c.cond.Wait()
	}
	if c.next >= len(c.done) || c.fail.failed() {
		return 0, false
	}
	fi := c.next
	c.next++
	return fi, true
}

// finish marks file fi as split, which may move the window.
func (c *fileClaims) finish(fi int) {
	c.mu.Lock()
	c.done[fi] = true
	for c.firstUndone < len(c.done) && c.done[c.firstUndone] {
		c.firstUndone++
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

// fileReader reads files and cuts them into chunks of complete elements, numbered
// within the file. Several reader goroutines share one fileReader; each works on the
// file it claimed. Per file, a read-ahead goroutine fills fixed-size blocks while the
// reader appends them to its current chunk buffer and finds element boundaries.
type fileReader struct {
	q          *jobQueue
	fail       *failure
	chunkSize  int
	freeBlocks chan []byte // read blocks, shared by all read-ahead goroutines

	readNs, stallNs, splitNs, inputBytes atomic.Int64
}

// run claims files until there are none left and reports each completed file's count.
func (r *fileReader) run(paths []string, claims *fileClaims, counts chan<- fileCount) {
	for {
		fi, ok := claims.claim()
		if !ok {
			return
		}
		n, ok := r.splitFile(fi, paths[fi])
		if ok {
			counts <- fileCount{fi, n}
		}
		claims.finish(fi)
	}
}

type block struct {
	b   []byte
	eof bool
	err error
}

// readAhead reads path in chunkSize blocks into blocks and closes it at the end.
func (r *fileReader) readAhead(path string, blocks chan<- block) {
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
		case b = <-r.freeBlocks:
		default:
			b = make([]byte, r.chunkSize)
		}
		t := time.Now()
		n, err := io.ReadFull(f, b[:cap(b)])
		r.readNs.Add(int64(time.Since(t)))
		eof := err == io.EOF || err == io.ErrUnexpectedEOF
		if err != nil && !eof {
			blocks <- block{err: err}
			return
		}
		t = time.Now()
		blocks <- block{b: b[:n], eof: eof}
		r.stallNs.Add(int64(time.Since(t)))
		if eof || r.fail.failed() {
			return
		}
	}
}

// splitFile puts every element of file fi into the queue, in chunks, and returns how
// many there were; false if the run failed.
func (r *fileReader) splitFile(fi int, path string) (int64, bool) {
	blocks := make(chan block, 4)
	go r.readAhead(path, blocks)
	var local int64
	var spans []span
	st := expectOpen
	buf := r.q.buffer(r.chunkSize)
	rescanAt := 0 // an unfinished element is rescanned only once the buffer has doubled
	for blk := range blocks {
		if r.fail.failed() {
			continue // drain so the read-ahead can stop
		}
		if blk.err != nil {
			r.fail.set(fmt.Errorf("%s: %w", path, blk.err))
			continue
		}
		if cap(buf)-len(buf)-jsonPadding < len(blk.b) { // an element longer than a chunk
			bigger := make([]byte, len(buf), 2*(len(buf)+len(blk.b))+jsonPadding)
			copy(bigger, buf)
			buf = bigger
		}
		buf = append(buf, blk.b...)
		r.inputBytes.Add(int64(len(blk.b)))
		select {
		case r.freeBlocks <- blk.b[:0]:
		default:
		}
		if len(buf) < rescanAt && !blk.eof {
			continue // still inside one large element; scanning it again now would be O(n^2)
		}
		t := time.Now()
		var consumed int
		var err error
		spans, consumed, err = splitElements(buf, &st, spans[:0])
		r.splitNs.Add(int64(time.Since(t)))
		if err != nil {
			r.fail.set(fmt.Errorf("%s: %w", path, err))
			continue
		}
		if len(spans) > 0 {
			// The unfinished tail moves to a fresh chunk before this one is handed over.
			tail := buf[consumed:]
			nb := append(r.q.buffer(max(r.chunkSize, 2*len(tail))), tail...)
			j := &streamJob{buf: buf[:consumed], spans: append([]span(nil), spans...), file: fi, local: local}
			local += int64(len(spans))
			r.q.put(j)
			buf = nb
			rescanAt = 0
		} else {
			// Drop what the scanner consumed ('[', ',', whitespace); the state remembers it.
			buf = buf[:copy(buf, buf[consumed:])]
			rescanAt = 2 * len(buf)
		}
		if blk.eof && (st != arrayDone || len(bytes.TrimSpace(buf)) > 0) {
			r.fail.set(fmt.Errorf("%s: the file ends inside the JSON array", path))
		}
	}
	return local, !r.fail.failed()
}
