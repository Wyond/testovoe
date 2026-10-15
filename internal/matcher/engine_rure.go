//go:build rure

package matcher

import (
	"regexp/syntax"
	"strings"

	rure "github.com/BurntSushi/rure-go"
)

// Rust's regex crate through github.com/BurntSushi/rure-go (cgo). librure is built
// from rust-lang/regex (regex-capi) by scripts/build_rure.sh and linked statically:
//
//	CGO_LDFLAGS="-L$PWD/third_party/lib" go build -tags rure ./...
//
// Rust regex is Unicode-aware by default: \d \w \s mean Unicode classes there and ASCII
// in Go. The prefilter's conditions are derived from Go's reading of each pattern, so
// Rust receives the pattern as Go's parser prints it back, where those classes are
// spelled out as ASCII ranges. Word boundaries are pinned to ASCII the same way.
func init() {
	registerEngine(&Engine{
		Name: "rure",
		Compile: func(expr string) (Re, error) {
			tree, err := syntax.Parse(expr, syntax.Perl)
			if err != nil {
				return nil, err
			}
			s := tree.String()
			s = strings.ReplaceAll(s, `\b`, `(?-u:\b)`)
			s = strings.ReplaceAll(s, `\B`, `(?-u:\B)`)
			re, err := rure.Compile(s)
			if err != nil {
				return nil, err
			}
			return rureRe{re}, nil
		},
	})
}

type rureRe struct{ re *rure.Regex }

func (r rureRe) Match(b []byte) bool { return r.re.IsMatchBytes(b) }
