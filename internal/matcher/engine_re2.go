//go:build re2_cgo

package matcher

import re2 "github.com/wasilibs/go-re2"

// Regexp is C++ RE2 through github.com/wasilibs/go-re2 in its native cgo mode (the
// same build tag selects that mode inside the library). Needs RE2 and pkg-config:
//
//	brew install re2 pkg-config
//	CGO_ENABLED=1 go build -tags re2_cgo ./...
type Regexp = re2.Regexp

const EngineName = "re2-cgo"

// RE2 does not let . (even with s) consume a byte that is not valid UTF-8, so
// (?s)^.*X is not equivalent to X there: "\xff<title>" matches the second only.
const dotMatchesInvalidUTF8 = false

func compileRegexp(expr string) (*Regexp, error) { return re2.Compile(expr) }
