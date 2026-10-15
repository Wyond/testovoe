//go:build pcre2

package matcher

/*
#cgo pkg-config: libpcre2-8
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <stdlib.h>

static pcre2_match_context *mctx;

// One shared match context: it only carries the limits and is never written after
// init, so concurrent pcre2_match calls may share it.
static void init_limits(uint32_t match_limit, uint32_t depth_limit) {
	mctx = pcre2_match_context_create(NULL);
	pcre2_set_match_limit(mctx, match_limit);
	pcre2_set_depth_limit(mctx, depth_limit);
}

static pcre2_code *compile(const char *pat, size_t n, uint32_t opts, int *err, size_t *off) {
	pcre2_code *re = pcre2_compile((PCRE2_SPTR)pat, n, opts, err, off, NULL);
	// JIT is opt-in: PCRE2 10.49's JIT with PCRE2_MATCH_INVALID_UTF reads past the end
	// of a subject that ends in an invalid UTF-8 byte (\b$ on "a\xff" depends on the byte
	// after the buffer; the interpreter is correct). See docs/EXPERIMENTS.md E19.
	const char *jit = getenv("WAAP_PCRE2_JIT");
	if (re && jit && jit[0] == '1') pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);
	return re;
}

// Match data per call keeps this thread-safe without per-thread state; it is one small
// allocation next to a match that the prefilter already made rare.
static int match(pcre2_code *re, const char *s, size_t n) {
	pcre2_match_data *md = pcre2_match_data_create(1, NULL);
	int rc = pcre2_match(re, (PCRE2_SPTR)s, n, 0, 0, md, mctx);
	pcre2_match_data_free(md);
	return rc;
}

static void errmsg(int err, char *buf, size_t n) { pcre2_get_error_message(err, (PCRE2_UCHAR *)buf, n); }
*/
import "C"

import (
	"fmt"
	"regexp/syntax"
	"unsafe"
)

// Limits for backtracking: a rule that exceeds them on some input is counted as
// inconclusive, never silently as "no match" (see Inconclusive).
const (
	pcreMatchLimit = 1_000_000
	pcreDepthLimit = 10_000
)

type pcreRe struct{ code *C.pcre2_code }

func (r *pcreRe) Match(b []byte) bool {
	var p *C.char
	if len(b) > 0 {
		p = (*C.char)(unsafe.Pointer(&b[0]))
	}
	rc := C.match(r.code, p, C.size_t(len(b)))
	switch {
	case rc >= 0:
		return true
	case rc == C.PCRE2_ERROR_NOMATCH:
		return false
	default: // match/depth limit, JIT stack, ...
		inconclusive.Add(1)
		return false
	}
}

// PCRE2 is run in UTF mode with $ meaning end of text only, so that its notion of a
// character and of $ agrees with the Go analysis the prefilter is built from. nmap
// itself uses PCRE on bytes; that difference is documented, not hidden.
func compilePCRE2(src, flags string) (Re, error) {
	opts := C.uint32_t(C.PCRE2_UTF | C.PCRE2_MATCH_INVALID_UTF | C.PCRE2_DOLLAR_ENDONLY)
	for _, f := range flags {
		switch f {
		case 'i':
			opts |= C.PCRE2_CASELESS
		case 's':
			opts |= C.PCRE2_DOTALL
		}
	}
	cs := C.CString(src)
	defer C.free(unsafe.Pointer(cs))
	var errc C.int
	var off C.size_t
	code := C.compile(cs, C.size_t(len(src)), opts, &errc, &off)
	if code == nil {
		buf := make([]byte, 256)
		C.errmsg(errc, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
		return nil, fmt.Errorf("pcre2 at offset %d: %s", off, C.GoString((*C.char)(unsafe.Pointer(&buf[0]))))
	}
	return &pcreRe{code}, nil // compiled patterns live for the whole process
}

func init() {
	C.init_limits(pcreMatchLimit, pcreDepthLimit)
	registerEngine(&Engine{
		Name: "pcre2",
		// A rule Go can compile is handed over as Go's parser prints it back, so that
		// classes like \s (which includes \v in PCRE but not in Go) mean the same thing
		// the prefilter assumed.
		Compile: func(expr string) (Re, error) {
			tree, err := syntax.Parse(expr, syntax.Perl)
			if err != nil {
				return nil, err
			}
			return compilePCRE2(tree.String(), "")
		},
		CompilePCRE: compilePCRE2,
	})
}
