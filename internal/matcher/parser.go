package matcher

import (
	"bytes"
	"fmt"
	"os"
	"sort"
)

// JSON parsers for the streaming mode. Each turns one array element, a
// {method,url,headers,data} object, into the normalized request (see appendRequest).
// "jx" is pure Go and the control; "simdjson" (build tag simdjson) is the SIMD one.
// Both must produce exactly the bytes of the prepared corpus: StreamNormalized is the
// check.

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

// maxKeptBuffer: a worker keeps buffers up to this size between messages.
const maxKeptBuffer = 8 << 20

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
