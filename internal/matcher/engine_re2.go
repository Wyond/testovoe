//go:build re2_cgo

package matcher

import re2 "github.com/wasilibs/go-re2"

// C++ RE2 through github.com/wasilibs/go-re2 in native cgo mode (the same build tag
// selects that mode inside the library). Needs: brew install re2 pkg-config.
func init() {
	registerEngine(&Engine{
		Name: "re2",
		Compile: func(expr string) (Re, error) {
			re, err := re2.Compile(expr)
			if err != nil {
				return nil, err
			}
			return re, nil
		},
	})
}
