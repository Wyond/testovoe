//go:build simdjson

package matcher

/*
#cgo CXXFLAGS: -std=c++17 -O3
#cgo pkg-config: simdjson
#include <stddef.h>
void *waap_sj_new(void);
void waap_sj_free(void *h);
size_t waap_sj_capacity(void *h);
const char *waap_sj_error(void *h);
const char *waap_sj_backend(void);
long long waap_sj_normalize(void *h, const char *msg, size_t len, size_t cap, char *out, size_t outcap, size_t *outlen);
void waap_sj_growths(void *h, long long *n, long long *bytes);
long long waap_sj_bench(void *h, const char *base, const size_t *offs, const size_t *lens, size_t n, size_t total, char *out, size_t outcap);
void waap_noop(void);
*/
import "C"

import (
	"errors"
	"unsafe"
)

// simdjson (C++, On-Demand API) through cgo. Built with -tags simdjson; needs
// `brew install simdjson`. ParserBackend reports the version and the implementation
// simdjson selected at run time (on Apple M4: "arm64 (ARM NEON)").
//
// Bytes cross into C as pointers into Go memory, valid for the duration of the call:
// the message (with jsonPadding readable bytes after it, which simdjson's SIMD stage
// reads) and the output buffer, which C fills. Nothing is retained after the call.
//
// A message simdjson rejects (it validates UTF-8 strictly and refuses lone surrogate
// escapes, both of which encoding/json and jx replace with U+FFFD) is parsed by jx
// instead, so both parsers always produce the same bytes. Such messages are counted
// (StreamResult.Parse, with simdjson's reason); malformed JSON still fails, because jx
// rejects it too. jx is never run first: it only sees what simdjson refused.
type sjParser struct {
	h   unsafe.Pointer
	fb  *jxParser
	pad []byte
	n   C.size_t // output length; a field, so passing its address to C does not allocate
	st  ParserStats
}

func (p *sjParser) stats() ParserStats {
	p.collectNative()
	return p.st
}

// collectNative moves the C++ growth counters of the current handle into p.st.
func (p *sjParser) collectNative() {
	var n, b C.longlong
	C.waap_sj_growths(p.h, &n, &b)
	p.st.NativeGrowths += int64(n)
	p.st.NativeGrowthBytes += int64(b)
}

func init() {
	parsers["simdjson"] = parserInfo{
		New: func() (msgParser, error) {
			return &sjParser{h: C.waap_sj_new(), fb: newJxParser(), st: ParserStats{Primary: "simdjson"}}, nil
		},
		Backend: func() string { return C.GoString(C.waap_sj_backend()) },
	}
}

func (p *sjParser) normalize(msg, dst []byte) ([]byte, error) {
	if len(msg) == 0 {
		return dst, errors.New("empty message")
	}
	if cap(msg)-len(msg) < jsonPadding { // not inside a padded chunk: copy once
		p.pad = append(append(p.pad[:0], msg...), make([]byte, jsonPadding)...)
		msg = p.pad[:len(msg)]
	}
	need := len(dst) + len(msg) + 64
	for {
		if cap(dst) < need {
			dst = append(dst[:len(dst):len(dst)], make([]byte, need-len(dst))...)[:len(dst)]
		}
		free := dst[len(dst):cap(dst)]
		r := C.waap_sj_normalize(p.h, (*C.char)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)), C.size_t(cap(msg)),
			(*C.char)(unsafe.Pointer(&free[0])), C.size_t(len(free)), &p.n)
		switch {
		case r == 0:
			p.st.PrimaryMsgs++
			return dst[:len(dst)+int(p.n)], nil
		case r > 0:
			need = len(dst) + int(r)
		default:
			p.st.FallbackMsgs++
			if p.st.Reasons == nil {
				p.st.Reasons = map[string]int64{}
			}
			p.st.Reasons[C.GoString(C.waap_sj_error(p.h))]++
			p.fb.msgs-- // counted here as a fallback, not as a jx message of its own
			return p.fb.normalize(msg, dst)
		}
	}
}

func (p *sjParser) trim() {
	if C.waap_sj_capacity(p.h) > maxKeptBuffer {
		p.collectNative()
		C.waap_sj_free(p.h)
		p.h = C.waap_sj_new()
	}
	if cap(p.pad) > maxKeptBuffer {
		p.pad = nil
	}
	p.fb.trim()
}

// Benchmark helpers (used by parse_bench_test.go; cgo is not allowed in _test.go files).

// cgoNoop is one empty call into C: the fixed price of every cgo transition.
func cgoNoop() { C.waap_noop() }

// sjBatch normalizes every message of base (offs/lens; each followed by at least
// jsonPadding bytes) in one cgo call. Compared with one call per message it shows the
// share of the per-message cgo transition.
func (p *sjParser) sjBatch(base []byte, offs, lens []int, out []byte) int64 {
	co, cl := make([]C.size_t, len(offs)), make([]C.size_t, len(lens))
	for i := range offs {
		co[i], cl[i] = C.size_t(offs[i]), C.size_t(lens[i])
	}
	return int64(C.waap_sj_bench(p.h, (*C.char)(unsafe.Pointer(&base[0])), &co[0], &cl[0], C.size_t(len(co)),
		C.size_t(len(base)), (*C.char)(unsafe.Pointer(&out[0])), C.size_t(len(out))))
}
