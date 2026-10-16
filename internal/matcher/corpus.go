package matcher

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-faster/jx"
)

// Corpus on disk (one directory):
//
//	corpus.bin   8-byte magic, then normalized requests back to back
//	corpus.idx   8-byte magic, uint64 count, then count+1 uint64 LE offsets into corpus.bin
//	manifest.json
//
// Request i is bin[off[i]:off[i+1]]. No length prefixes: the offsets are enough.
const (
	binMagic      = "WAAPBIN1"
	idxMagic      = "WAAPIDX1"
	NormVersion   = 1
	FormatVersion = 1
)

type ManifestFile struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Requests int    `json:"requests"`
}

type Manifest struct {
	FormatVersion  int            `json:"format_version"`
	NormVersion    int            `json:"normalization_version"`
	Normalization  string         `json:"normalization"`
	Requests       int            `json:"request_count"`
	PayloadBytes   int64          `json:"normalized_payload_bytes"`
	InputBytes     int64          `json:"input_json_bytes"`
	ConvertSec     float64        `json:"conversion_seconds"`
	Workers        int            `json:"conversion_workers"`
	Decoder        string         `json:"json_decoder"`
	Allocs         uint64         `json:"conversion_heap_allocs"`
	AllocBytes     uint64         `json:"conversion_heap_alloc_bytes"`
	NumGC          uint32         `json:"conversion_gc_cycles"`
	InflightMB     int64          `json:"conversion_inflight_mb"`
	LongestFileSec float64        `json:"conversion_longest_file_seconds"`
	WriterWaitSec  float64        `json:"conversion_writer_wait_seconds"`
	WriterWriteSec float64        `json:"conversion_writer_write_seconds"`
	Files          []ManifestFile `json:"files"`
}

const normDescription = "METHOD SP URL SP HTTP/1.1 CRLF, then 'Name: value CRLF' per header in JSON order and original case, CRLF, body. " +
	"JSON string escapes decoded; no percent-decoding, no case folding, body not truncated."

// appendRequest is the one normalization function. hdr is the already serialized header block.
func appendRequest[S string | []byte](dst []byte, method, url S, hdr []byte, body S) []byte {
	dst = append(dst, method...)
	dst = append(dst, ' ')
	dst = append(dst, url...)
	dst = append(dst, " HTTP/1.1\r\n"...)
	dst = append(dst, hdr...)
	dst = append(dst, "\r\n"...)
	return append(dst, body...)
}

// normalizeFileStd streams one JSON array of {method,url,headers,data} objects with
// encoding/json and returns the normalized requests back to back plus the end offset of
// each. Every token comes back as a freshly allocated string. Kept for comparison with
// normalizeFileJx, see docs/EXPERIMENTS.md E14.
func normalizeFileStd(path string) (buf []byte, ends []int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(bufio.NewReaderSize(f, 1<<20))
	dec.UseNumber()

	scalar := func() (string, error) {
		t, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch v := t.(type) {
		case string:
			return v, nil
		case json.Number:
			return v.String(), nil
		case bool:
			return fmt.Sprint(v), nil
		case json.Delim: // nested value where a scalar was expected: skip, treat as empty
			for depth := 1; depth > 0; {
				t, err := dec.Token()
				if err != nil {
					return "", err
				}
				if d, ok := t.(json.Delim); ok {
					if d == '{' || d == '[' {
						depth++
					} else {
						depth--
					}
				}
			}
		}
		return "", nil // null
	}

	var hdr []byte
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return nil, nil, fmt.Errorf("expected a JSON array: %v", err)
	}
	for dec.More() {
		if t, err := dec.Token(); err != nil || t != json.Delim('{') {
			return nil, nil, fmt.Errorf("expected an object: %v", err)
		}
		var method, url, body string
		hdr = hdr[:0]
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, nil, err
			}
			switch key, _ := kt.(string); key {
			case "method":
				method, err = scalar()
			case "url":
				url, err = scalar()
			case "data":
				body, err = scalar()
			case "headers":
				var t json.Token
				if t, err = dec.Token(); err == nil && t == json.Delim('{') {
					for dec.More() {
						k, kerr := dec.Token()
						if kerr != nil {
							return nil, nil, kerr
						}
						v, verr := scalar()
						if verr != nil {
							return nil, nil, verr
						}
						name, _ := k.(string)
						hdr = append(hdr, name...)
						hdr = append(hdr, ": "...)
						hdr = append(hdr, v...)
						hdr = append(hdr, "\r\n"...)
					}
					_, err = dec.Token() // }
				} else if err == nil && t != nil {
					err = fmt.Errorf("headers must be an object or null, got %v", t)
				}
			default:
				_, err = scalar()
			}
			if err != nil {
				return nil, nil, err
			}
		}
		if _, err := dec.Token(); err != nil { // }
			return nil, nil, err
		}
		buf = appendRequest(buf, method, url, hdr, body)
		ends = append(ends, len(buf))
	}
	if _, err := dec.Token(); err != nil { // ]
		return nil, nil, err
	}
	return buf, ends, nil
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

// jxObject turns one {method,url,headers,data} object into a normalized request. Its
// four field buffers and the callbacks are allocated once and reused for every object.
// Scalars are written the way normalizeFileStd writes them: numbers as their JSON text,
// booleans as true/false, null and nested values as empty.
type jxObject struct {
	method, url, hdr, body []byte
	header, field          func(*jx.Decoder, []byte) error
}

func newJxObject() *jxObject {
	o := &jxObject{}
	o.header = func(d *jx.Decoder, name []byte) error {
		o.hdr = append(o.hdr, name...)
		o.hdr = append(o.hdr, ": "...)
		var err error
		if o.hdr, err = jxScalar(d, o.hdr); err != nil {
			return err
		}
		o.hdr = append(o.hdr, "\r\n"...)
		return nil
	}
	o.field = func(d *jx.Decoder, key []byte) error {
		var err error
		switch string(key) { // no allocation: the compiler compares bytes in place
		case "method":
			o.method, err = jxScalar(d, o.method[:0])
		case "url":
			o.url, err = jxScalar(d, o.url[:0])
		case "data":
			o.body, err = jxScalar(d, o.body[:0])
		case "headers":
			switch t := d.Next(); t {
			case jx.Object:
				err = d.ObjBytes(o.header)
			case jx.Null:
				err = d.Null()
			default:
				err = fmt.Errorf("headers must be an object or null, got %v", t)
			}
		default:
			err = d.Skip()
		}
		return err
	}
	return o
}

// decode reads the object d is positioned at and appends the normalized request to dst.
func (o *jxObject) decode(d *jx.Decoder, dst []byte) ([]byte, error) {
	o.method, o.url, o.hdr, o.body = o.method[:0], o.url[:0], o.hdr[:0], o.body[:0]
	if err := d.ObjBytes(o.field); err != nil {
		return dst, err
	}
	return appendRequest(dst, o.method, o.url, o.hdr, o.body), nil
}

func jxScalar(d *jx.Decoder, dst []byte) ([]byte, error) {
	switch d.Next() {
	case jx.String:
		return d.StrAppend(dst)
	case jx.Number:
		n, err := d.Num()
		return append(dst, n...), err
	case jx.Bool:
		v, err := d.Bool()
		return strconv.AppendBool(dst, v), err
	case jx.Null:
		return dst, d.Null()
	default: // nested value where a scalar was expected: skip, treat as empty
		return dst, d.Skip()
	}
}

// Decoders available to Convert.
var decoders = map[string]func(string) ([]byte, []int, error){
	"std":     normalizeFileStd,
	"jx":      func(p string) ([]byte, []int, error) { return normalizeFileJx(p, false) },
	"jxbytes": func(p string) ([]byte, []int, error) { return normalizeFileJx(p, true) },
}

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

// Store is read-only access to a converted corpus. The offsets (8 bytes per request) are
// read into the heap. The payload is reachable two ways: Request slices a read-only
// mmap of the file, ReadRange copies a run of requests into a caller-owned buffer with
// pread. Which one the matcher uses is a measured choice, see docs/EXPERIMENTS.md.
type Store struct {
	Manifest Manifest
	bin      []byte
	offs     []uint64
	f        *os.File
}

func OpenStore(dir string) (*Store, error) {
	s := &Store{}
	mj, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(mj, &s.Manifest); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if s.Manifest.FormatVersion != FormatVersion || s.Manifest.NormVersion != NormVersion {
		return nil, fmt.Errorf("corpus has format %d / normalization %d, this binary expects %d / %d: re-run prepare",
			s.Manifest.FormatVersion, s.Manifest.NormVersion, FormatVersion, NormVersion)
	}
	idx, err := os.ReadFile(filepath.Join(dir, "corpus.idx"))
	if err != nil {
		return nil, err
	}
	if len(idx) < 16 || string(idx[:8]) != idxMagic {
		return nil, errors.New("corpus.idx: bad magic")
	}
	count := binary.LittleEndian.Uint64(idx[8:])
	if count > uint64(len(idx))/8 || count != uint64(s.Manifest.Requests) || uint64(len(idx)-16)/8 != count+1 || (len(idx)-16)%8 != 0 {
		return nil, fmt.Errorf("corpus.idx: %d requests in header, %d offsets, manifest says %d",
			count, (len(idx)-16)/8, s.Manifest.Requests)
	}
	f, err := os.Open(filepath.Join(dir, "corpus.bin"))
	if err != nil {
		return nil, err
	}
	s.f = f
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	var magic [8]byte
	fail := func(err error) (*Store, error) {
		f.Close()
		return nil, err
	}
	if _, err := io.ReadFull(f, magic[:]); err != nil || string(magic[:]) != binMagic {
		return fail(errors.New("corpus.bin: bad magic"))
	}
	s.offs = make([]uint64, count+1)
	prev := uint64(len(binMagic))
	for i := range s.offs {
		o := binary.LittleEndian.Uint64(idx[16+8*i:])
		if o < prev || o > uint64(st.Size()) {
			return fail(fmt.Errorf("corpus.idx: offset %d of request %d is out of order or past the end (%d)", o, i, st.Size()))
		}
		s.offs[i], prev = o, o
	}
	if s.offs[0] != uint64(len(binMagic)) || s.offs[count] != uint64(st.Size()) {
		return fail(fmt.Errorf("corpus.bin is %d bytes, index covers %d..%d", st.Size(), s.offs[0], s.offs[count]))
	}
	s.bin, err = syscall.Mmap(int(f.Fd()), 0, int(st.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return fail(fmt.Errorf("mmap: %w", err))
	}
	return s, nil
}

func (s *Store) Count() int { return len(s.offs) - 1 }

// Request returns request id as a slice of the mapping: valid until Close, never written.
func (s *Store) Request(id int) []byte { return s.bin[s.offs[id]:s.offs[id+1]:s.offs[id+1]] }

// ReadRange reads requests [first, last) into buf (grown if needed) and returns the
// buffer plus the file offset of its first byte: request id is at
// buf[Offset(id)-base : Offset(id+1)-base].
func (s *Store) ReadRange(first, last int, buf []byte) ([]byte, uint64, error) {
	base, n := s.offs[first], int(s.offs[last]-s.offs[first])
	if cap(buf) < n {
		buf = make([]byte, n+n/4)
	}
	buf = buf[:n]
	if _, err := s.f.ReadAt(buf, int64(base)); err != nil {
		return nil, 0, fmt.Errorf("reading requests %d..%d: %w", first, last, err)
	}
	return buf, base, nil
}

// Offset is the position of request id in corpus.bin.
func (s *Store) Offset(id int) uint64 { return s.offs[id] }

// Close unmaps the corpus. Call it only after every worker has finished.
func (s *Store) Close() error { return errors.Join(syscall.Munmap(s.bin), s.f.Close()) }
