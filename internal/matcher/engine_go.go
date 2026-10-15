//go:build !re2_cgo

package matcher

import "regexp"

// Regexp is the confirming engine. The default build uses Go's standard library;
// building with -tags re2_cgo swaps in C++ RE2 (engine_re2.go). Everything else,
// including the prefilter, is the same code.
type Regexp = regexp.Regexp

// EngineName goes into reports and metrics so results of the two builds are never mixed.
const EngineName = "go-regexp"

// dotMatchesInvalidUTF8: Go decodes an invalid byte as U+FFFD, which (?s). matches.
// The (?s)^.*X -> X rewrite in analyze is only exact when this holds.
const dotMatchesInvalidUTF8 = true

func compileRegexp(expr string) (*Regexp, error) { return regexp.Compile(expr) }
