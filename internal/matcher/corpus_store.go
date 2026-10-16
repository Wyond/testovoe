package matcher

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
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
