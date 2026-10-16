//go:build pcre2

package matcher

/*
#cgo pkg-config: libpcre2-8
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <stdlib.h>

static pcre2_match_context *omctx;

static void oracle_init(uint32_t match_limit, uint32_t depth_limit) {
	omctx = pcre2_match_context_create(NULL);
	pcre2_set_match_limit(omctx, match_limit);
	pcre2_set_depth_limit(omctx, depth_limit);
}

// Byte mode, as nmap compiles service rules: no UTF, only the rule's own i/s flags, so a
// character is a byte and $ also matches before a final newline.
static pcre2_code *oracle_compile(const char *pat, size_t n, uint32_t opts, int *err, size_t *off) {
	pcre2_code *re = pcre2_compile((PCRE2_SPTR)pat, n, opts, err, off, NULL);
	if (re) pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);
	return re;
}

static pcre2_match_data *oracle_md(void) { return pcre2_match_data_create(1, NULL); }
static void oracle_md_free(pcre2_match_data *md) { pcre2_match_data_free(md); }

static int oracle_match(pcre2_code *re, const char *s, size_t n, pcre2_match_data *md) {
	int rc = pcre2_match(re, (PCRE2_SPTR)s, n, 0, 0, md, omctx);
	if (rc == PCRE2_ERROR_JIT_STACKLIMIT) rc = pcre2_match(re, (PCRE2_SPTR)s, n, 0, PCRE2_NO_JIT, md, omctx);
	return rc;
}

static void oracle_errmsg(int err, char *buf, size_t n) { pcre2_get_error_message(err, (PCRE2_UCHAR *)buf, n); }
*/
import "C"

import (
	"bytes"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
	"unsafe"
)

// OracleRule counts, for one rule, the sampled requests on which the matcher and the
// byte-mode reference disagree.
type OracleRule struct {
	*Pattern
	Missed, Extra           int64 // reference matches and we do not; we match and it does not
	MissedASCII, ExtraASCII int64 // the same, on requests made only of ASCII bytes
	Example                 int   // a request id with a disagreement
	// The reference hit its backtracking limit on this rule (its answer is unknown and
	// does not count as a disagreement): where we matched, and where we did not.
	LimitOurs, LimitNone int64
}

type OracleReport struct {
	Requests, NonASCII, InvalidUTF8 int64
	Inconclusive                    int64 // reference hit its match/depth limit (counted as no match)
	PatternDiff, ServiceDiff        int64 // requests whose matched rules / output line differ
	HardDiff                        int64 // requests whose first hard service differs
	Matches, RefMatches             int64
	Rules                           []OracleRule // only rules with a disagreement, most first
	Seconds                         float64
}

// Oracle runs every rule of m, compiled by PCRE2 in byte mode from its source as written
// in the file, on each given request without any prefilter, and compares the result
// with m.MatchFast. The reference is meant to stand in for nmap's own matching; it does
// not reproduce nmap's PCRE limits, only ours.
func Oracle(m *Matcher, s *Store, ids []int, workers int) (*OracleReport, error) {
	C.oracle_init(pcreMatchLimit, pcreDepthLimit)
	if len(m.Rules.Unsupported) > 0 || len(m.Rules.BadLines) > 0 {
		return nil, fmt.Errorf("%d rules unsupported, %d lines unparsed: the comparison needs every rule", len(m.Rules.Unsupported), len(m.Rules.BadLines))
	}
	ref := make([]*C.pcre2_code, len(m.Rules.Patterns))
	for i, p := range m.Rules.Patterns {
		opts := C.uint32_t(0)
		if strings.Contains(p.Flags, "i") {
			opts |= C.PCRE2_CASELESS
		}
		if strings.Contains(p.Flags, "s") {
			opts |= C.PCRE2_DOTALL
		}
		cs := C.CString(p.Source)
		var errc C.int
		var off C.size_t
		ref[i] = C.oracle_compile(cs, C.size_t(len(p.Source)), opts, &errc, &off)
		C.free(unsafe.Pointer(cs))
		if ref[i] == nil {
			buf := make([]byte, 256)
			C.oracle_errmsg(errc, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
			return nil, fmt.Errorf("line %d: byte-mode PCRE2 rejects the rule at offset %d: %s", p.Line, off, C.GoString((*C.char)(unsafe.Pointer(&buf[0]))))
		}
	}

	if workers < 1 {
		workers = runtime.NumCPU()
	}
	n := len(m.Rules.Patterns)
	type local struct {
		missed, extra, missedA, extraA []int64
		limitOurs, limitNone           []int64
		example                        []int
		rep                            OracleReport
	}
	locals := make([]*local, workers)
	var next atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for wi := range workers {
		l := &local{missed: make([]int64, n), extra: make([]int64, n), missedA: make([]int64, n), extraA: make([]int64, n),
			limitOurs: make([]int64, n), limitNone: make([]int64, n), example: make([]int, n)}
		locals[wi] = l
		wg.Add(1)
		go func() {
			defer wg.Done()
			md := C.oracle_md()
			defer C.oracle_md_free(md)
			w := m.NewWorker()
			var ours, theirs, limited []uint32
			isLimited := make([]bool, n)
			var lineOurs, lineRef []byte
			for {
				k := int(next.Add(1) - 1)
				if k >= len(ids) {
					return
				}
				id := ids[k]
				req := s.Request(id)
				ascii := true
				for _, c := range req {
					if c >= 0x80 {
						ascii = false
						break
					}
				}
				l.rep.Requests++
				if !ascii {
					l.rep.NonASCII++
					if !utf8.Valid(req) {
						l.rep.InvalidUTF8++
					}
				}
				ours = append(ours[:0], m.MatchFast(req, w)...)
				theirs, limited = theirs[:0], limited[:0]
				var p *C.char
				if len(req) > 0 {
					p = (*C.char)(unsafe.Pointer(&req[0]))
				}
				for i, re := range ref {
					rc := C.oracle_match(re, p, C.size_t(len(req)), md)
					switch {
					case rc >= 0:
						theirs = append(theirs, uint32(i))
					case rc != C.PCRE2_ERROR_NOMATCH:
						l.rep.Inconclusive++
						limited = append(limited, uint32(i))
					}
				}
				// A rule whose reference answer is unknown is left out of the comparison.
				if len(limited) > 0 {
					for _, x := range limited {
						isLimited[x] = true
					}
					kept := ours[:0]
					for _, x := range ours {
						if isLimited[x] {
							l.limitOurs[x]++
							isLimited[x] = false
						} else {
							kept = append(kept, x)
						}
					}
					for _, x := range limited {
						if isLimited[x] {
							l.limitNone[x]++
							isLimited[x] = false
						}
					}
					ours = kept
				}
				l.rep.Matches += int64(len(ours))
				l.rep.RefMatches += int64(len(theirs))
				// Both lists are ascending; walk them together.
				diff := false
				for a, b := 0, 0; a < len(ours) || b < len(theirs); {
					switch {
					case b == len(theirs) || a < len(ours) && ours[a] < theirs[b]:
						l.extra[ours[a]]++
						if ascii {
							l.extraA[ours[a]]++
						}
						l.example[ours[a]] = id
						a++
						diff = true
					case a == len(ours) || theirs[b] < ours[a]:
						l.missed[theirs[b]]++
						if ascii {
							l.missedA[theirs[b]]++
						}
						l.example[theirs[b]] = id
						b++
						diff = true
					default:
						a++
						b++
					}
				}
				if diff {
					l.rep.PatternDiff++
					lineOurs = m.appendResultTail(lineOurs[:0], ours, w)
					lineRef = m.appendResultTail(lineRef[:0], theirs, w)
					if !bytes.Equal(lineOurs, lineRef) {
						l.rep.ServiceDiff++
					}
					if m.firstHard(ours) != m.firstHard(theirs) {
						l.rep.HardDiff++
					}
				}
			}
		}()
	}
	wg.Wait()

	rep := &OracleReport{Seconds: time.Since(start).Seconds()}
	for i, p := range m.Rules.Patterns {
		r := OracleRule{Pattern: p, Example: -1}
		for _, l := range locals {
			r.Missed += l.missed[i]
			r.Extra += l.extra[i]
			r.MissedASCII += l.missedA[i]
			r.ExtraASCII += l.extraA[i]
			if l.missed[i]+l.extra[i] > 0 {
				r.Example = l.example[i]
			}
			r.LimitOurs += l.limitOurs[i]
			r.LimitNone += l.limitNone[i]
		}
		if r.Missed+r.Extra+r.LimitOurs+r.LimitNone > 0 {
			rep.Rules = append(rep.Rules, r)
		}
	}
	for _, l := range locals {
		rep.Requests += l.rep.Requests
		rep.NonASCII += l.rep.NonASCII
		rep.InvalidUTF8 += l.rep.InvalidUTF8
		rep.Inconclusive += l.rep.Inconclusive
		rep.PatternDiff += l.rep.PatternDiff
		rep.ServiceDiff += l.rep.ServiceDiff
		rep.HardDiff += l.rep.HardDiff
		rep.Matches += l.rep.Matches
		rep.RefMatches += l.rep.RefMatches
	}
	sort.Slice(rep.Rules, func(a, b int) bool {
		x, y := rep.Rules[a], rep.Rules[b]
		if x.Missed+x.Extra != y.Missed+y.Extra {
			return x.Missed+x.Extra > y.Missed+y.Extra
		}
		if x.LimitOurs+x.LimitNone != y.LimitOurs+y.LimitNone {
			return x.LimitOurs+x.LimitNone > y.LimitOurs+y.LimitNone
		}
		return x.Line < y.Line
	})
	return rep, nil
}

// firstHard is the service of the first hard match in priority order, "" if none.
func (m *Matcher) firstHard(ids []uint32) string {
	for _, id := range ids {
		if p := m.Rules.Patterns[id]; p.Kind == Hard {
			return p.Service
		}
	}
	return ""
}
