package matcher

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-faster/jx"
)

// Converting the JSON files into the binary corpus of corpus_store.go: files are
// normalized in parallel and written strictly in order, so request ids are stable.

// InputFiles lists every *.json under dirs: dirs in the given order, files inside a dir
// by lexical path. Request ids follow this order in both Convert and RunStream.
func InputFiles(dirs []string) ([]string, error) {
	var paths []string
	for _, d := range dirs {
		var fs []string
		err := filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error {
			if err == nil && !e.IsDir() && strings.HasSuffix(p, ".json") && !strings.HasPrefix(e.Name(), "._") {
				fs = append(fs, p)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		if len(fs) == 0 {
			return nil, fmt.Errorf("no *.json under %s", d)
		}
		sort.Strings(fs)
		paths = append(paths, fs...)
	}
	return paths, nil
}

// normalizeFileJx does the same with github.com/go-faster/jx. Strings are unescaped
// straight into four buffers that live for the whole file (method, url, header block,
// body) and object keys are compared as byte slices. Reading from a stream, jx still
// copies each object key (about 18 allocations per request); with wholeFile it decodes
// from the file contents in memory and allocates almost nothing, at the price of
// holding the whole JSON file. Scalars are written the way normalizeFileStd writes them:
// numbers as their JSON text, booleans as true/false, null and nested values as empty.
func normalizeFileJx(path string, wholeFile bool) (buf []byte, ends []int, err error) {
	var d *jx.Decoder
	if wholeFile {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		d = jx.DecodeBytes(data) // keys and unescaped strings can point into data: no copies
		buf = make([]byte, 0, len(data))
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return nil, nil, err
		}
		// Normalized output is smaller than the JSON (no quotes, keys, escapes), so one
		// allocation of the file size replaces the repeated grow-and-copy of append.
		buf = make([]byte, 0, st.Size())
		d = jx.Decode(f, 1<<20)
	}
	obj := newJxObject()
	if d.Next() != jx.Array {
		return nil, nil, errors.New("expected a JSON array")
	}
	err = d.Arr(func(d *jx.Decoder) error {
		if d.Next() != jx.Object {
			return errors.New("expected an object")
		}
		var err error
		if buf, err = obj.decode(d, buf); err != nil {
			return err
		}
		ends = append(ends, len(buf))
		return nil
	})
	return buf, ends, err
}

// Decoders available to Convert.
var decoders = map[string]func(string) ([]byte, []int, error){
	"std":     normalizeFileStd,
	"jx":      func(p string) ([]byte, []int, error) { return normalizeFileJx(p, false) },
	"jxbytes": func(p string) ([]byte, []int, error) { return normalizeFileJx(p, true) },
}

// Convert normalizes every *.json under dirs (dirs in the given order, files inside a dir
// by lexical relative path) and writes the corpus to outDir. Files are decoded in
// parallel but written strictly in order, so request ids are stable. At most `workers`
// decoded files are held in memory. The three output files appear under their final
// names only after everything succeeded.
func Convert(dirs []string, outDir string, workers int, decoder string, inflightBytes int64) (*Manifest, error) {
	normalizeFile, ok := decoders[decoder]
	if !ok {
		return nil, fmt.Errorf("unknown JSON decoder %q (jx, jxbytes or std)", decoder)
	}
	if workers < 1 {
		workers = 1
	}
	var ms0 runtime.MemStats
	runtime.ReadMemStats(&ms0)
	start := time.Now()
	m := &Manifest{FormatVersion: FormatVersion, NormVersion: NormVersion, Normalization: normDescription, Workers: workers, Decoder: decoder, InflightMB: inflightBytes >> 20}
	paths, err := InputFiles(dirs)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	binTmp, idxTmp := filepath.Join(outDir, "corpus.bin.tmp"), filepath.Join(outDir, "corpus.idx.tmp")
	binF, err := os.Create(binTmp)
	if err != nil {
		return nil, err
	}
	defer binF.Close()
	idxF, err := os.Create(idxTmp)
	if err != nil {
		return nil, err
	}
	defer idxF.Close()
	binW, idxW := bufio.NewWriterSize(binF, 4<<20), bufio.NewWriterSize(idxF, 1<<20)
	binW.WriteString(binMagic)
	idxW.WriteString(idxMagic)
	var u8 [8]byte
	idxW.Write(u8[:]) // count, patched at the end
	putU64 := func(v uint64) {
		binary.LittleEndian.PutUint64(u8[:], v)
		idxW.Write(u8[:])
	}

	type result struct {
		buf  []byte
		ends []int
		err  error
		sec  float64
	}
	results := make([]chan result, len(paths))
	for i := range results {
		results[i] = make(chan result, 1)
	}
	// Files are claimed in order, but a worker may run ahead of the writer as long as
	// the JSON bytes of claimed-but-unwritten files stay within inflightBytes. A count
	// limit ("at most `workers` files ahead") let one 700 MB file stall every other worker
	// until the writer got past it (E14). The file the writer needs next may always be
	// claimed, so a single file larger than the budget cannot deadlock the loop.
	sizes := make([]int64, len(paths))
	for i, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		sizes[i] = st.Size()
	}
	var (
		mu       sync.Mutex
		cond     = sync.NewCond(&mu)
		next     int   // next file to claim
		written  int   // files the writer has consumed
		inFlight int64 // JSON bytes of claimed, unwritten files
		wg       sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				for next < len(paths) && next != written && inFlight+sizes[next] > inflightBytes {
					cond.Wait()
				}
				if next >= len(paths) {
					mu.Unlock()
					return
				}
				i := next
				next++
				inFlight += sizes[i]
				mu.Unlock()
				var r result
				t := time.Now()
				r.buf, r.ends, r.err = normalizeFile(paths[i])
				r.sec = time.Since(t).Seconds()
				results[i] <- r
			}
		}()
	}
	off := uint64(len(binMagic))
	putU64(off)
	var firstErr error
	for i, p := range paths {
		tw := time.Now()
		r := <-results[i]
		m.WriterWaitSec += time.Since(tw).Seconds()
		mu.Lock()
		written = i + 1
		inFlight -= sizes[i]
		cond.Broadcast()
		mu.Unlock()
		m.LongestFileSec = max(m.LongestFileSec, r.sec)
		if firstErr != nil {
			continue // keep draining so workers can finish
		}
		if r.err != nil {
			firstErr = fmt.Errorf("%s: %w", p, r.err)
			continue
		}
		tw = time.Now()
		if _, err := binW.Write(r.buf); err != nil {
			firstErr = err
			continue
		}
		m.WriterWriteSec += time.Since(tw).Seconds()
		for _, e := range r.ends {
			putU64(off + uint64(e))
		}
		off += uint64(len(r.buf))
		m.Files = append(m.Files, ManifestFile{Path: p, Size: sizes[i], Requests: len(r.ends)})
		m.Requests += len(r.ends)
		m.PayloadBytes += int64(len(r.buf))
		m.InputBytes += sizes[i]
	}
	wg.Wait()
	if firstErr != nil {
		os.Remove(binTmp)
		os.Remove(idxTmp)
		return nil, firstErr
	}
	fail := func(err error) (*Manifest, error) {
		for _, n := range []string{"corpus.bin", "corpus.idx", "manifest.json"} {
			os.Remove(filepath.Join(outDir, n+".tmp"))
		}
		return nil, err
	}
	if err := errors.Join(binW.Flush(), idxW.Flush()); err != nil {
		return fail(err)
	}
	binary.LittleEndian.PutUint64(u8[:], uint64(m.Requests))
	if _, err := idxF.WriteAt(u8[:], int64(len(idxMagic))); err != nil {
		return fail(err)
	}
	if err := errors.Join(binF.Close(), idxF.Close()); err != nil {
		return fail(err)
	}
	m.ConvertSec = time.Since(start).Seconds()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m.Allocs, m.AllocBytes, m.NumGC = ms.Mallocs-ms0.Mallocs, ms.TotalAlloc-ms0.TotalAlloc, ms.NumGC-ms0.NumGC
	mj, _ := json.MarshalIndent(m, "", " ")
	manTmp := filepath.Join(outDir, "manifest.json.tmp")
	if err := os.WriteFile(manTmp, mj, 0o644); err != nil {
		return fail(err)
	}
	for _, n := range []string{"corpus.bin", "corpus.idx", "manifest.json"} {
		if err := os.Rename(filepath.Join(outDir, n+".tmp"), filepath.Join(outDir, n)); err != nil {
			return fail(err)
		}
	}
	return m, nil
}
