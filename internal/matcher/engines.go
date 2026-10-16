package matcher

import (
	"regexp"
	"sort"
	"sync/atomic"
	"unicode/utf8"
)

// Re is a compiled pattern of any engine. Implementations must be safe for concurrent use.
type Re interface{ Match([]byte) bool }

// utf8Aware is implemented by engines whose behaviour depends on whether the input is
// valid UTF-8 (PCRE2 picks JIT or the interpreter by it). The matcher computes validity
// once per request instead of once per call.
type utf8Aware interface {
	MatchUTF8(b []byte, valid bool) bool
}

// reqInput caches per-request facts that some engines want.
type reqInput struct {
	b     []byte
	known bool
	valid bool
}

func (in *reqInput) match(re Re) bool {
	if u, ok := re.(utf8Aware); ok {
		if !in.known {
			in.valid, in.known = utf8.Valid(in.b), true
		}
		return u.MatchUTF8(in.b, in.valid)
	}
	return re.Match(in.b)
}

// Engine is one confirming regex engine. Go's regexp is always available; the others
// are compiled in with build tags (re2_cgo, rure, pcre2) and register themselves.
type Engine struct {
	Name string
	// Compile takes the pattern as Go/RE2 syntax with the nmap flags as a (?is) prefix.
	Compile func(expr string) (Re, error)
	// CompilePCRE takes the original PCRE source and nmap flags; nil if unsupported.
	// Used only for the rules Go cannot compile.
	CompilePCRE func(src, flags string) (Re, error)
	// DotMatchesInvalidUTF8: (?s). consumes any byte. Go: yes (an invalid byte is one
	// U+FFFD). RE2, Rust regex, PCRE2 in UTF mode: no. The (?s)^.*X -> X rewrite is only
	// exact when this holds.
	DotMatchesInvalidUTF8 bool
}

var engines = map[string]*Engine{}

func registerEngine(e *Engine) { engines[e.Name] = e }

// EngineNames lists the engines compiled into this binary.
func EngineNames() []string {
	var n []string
	for k := range engines {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// inconclusive counts matches an engine gave up on (PCRE2 hitting its match limit).
// Such a pattern is reported as not matched, so the count must be published with the
// results instead of being hidden.
var inconclusive atomic.Uint64

func Inconclusive() uint64 { return inconclusive.Load() }

func init() {
	registerEngine(&Engine{
		Name: "go",
		Compile: func(expr string) (Re, error) {
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, err
			}
			return re, nil
		},
		DotMatchesInvalidUTF8: true,
	})
}
