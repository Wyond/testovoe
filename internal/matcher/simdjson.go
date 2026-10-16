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
// (StreamResult.Fallbacks); malformed JSON still fails, because jx rejects it too.
type sjParser struct {
	h   unsafe.Pointer
	fb  *jxParser
	pad []byte
	n   C.size_t // output length; a field, so passing its address to C does not allocate
}

func init() {
	parsers["simdjson"] = parserInfo{
		New: func() (msgParser, error) {
			return &sjParser{h: C.waap_sj_new(), fb: newJxParser()}, nil
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
			return dst[:len(dst)+int(p.n)], nil
		case r > 0:
			need = len(dst) + int(r)
		default:
			jsonFallbacks.Add(1)
			return p.fb.normalize(msg, dst)
		}
	}
}

func (p *sjParser) trim() {
	if C.waap_sj_capacity(p.h) > maxKeptBuffer {
		C.waap_sj_free(p.h)
		p.h = C.waap_sj_new()
	}
	if cap(p.pad) > maxKeptBuffer {
		p.pad = nil
	}
	p.fb.trim()
}
