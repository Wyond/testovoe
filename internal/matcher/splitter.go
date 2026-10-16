package matcher

import (
	"bytes"
	"fmt"
)

// Element boundaries in a JSON array. The source files are single-line JSON arrays of
// objects, not JSONL, so element boundaries are found by a small scanner that only
// tracks strings (with backslash escapes) and nesting depth. It does not validate the
// element: the parser does, and a malformed element or array is an error, never an
// empty request.

type arrayState uint8

const (
	expectOpen    arrayState = iota // before '['
	expectFirst                     // after '[': element or ']'
	expectElement                   // after ',': element
	expectComma                     // after an element: ',' or ']'
	arrayDone                       // after ']': only whitespace
)

type span struct{ start, end int }

// splitElements finds the complete array elements in b, continuing from state *st. It
// returns them and how many bytes were consumed; an element cut off by the end of b is
// left unconsumed for the next call.
func splitElements(b []byte, st *arrayState, spans []span) ([]span, int, error) {
	i := 0
	for i < len(b) {
		c := b[i]
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			i++
			continue
		}
		switch *st {
		case expectOpen:
			if c != '[' {
				return spans, i, fmt.Errorf("expected '[' at the start of the file, got %q", c)
			}
			*st = expectFirst
			i++
		case expectFirst, expectElement:
			if c == ']' && *st == expectFirst {
				*st = arrayDone
				i++
				continue
			}
			if c != '{' {
				return spans, i, fmt.Errorf("array element is not an object (starts with %q)", c)
			}
			end := objectEnd(b, i)
			if end < 0 {
				return spans, i, nil // incomplete: wait for more data
			}
			spans = append(spans, span{i, end})
			*st = expectComma
			i = end
		case expectComma:
			switch c {
			case ',':
				*st = expectElement
			case ']':
				*st = arrayDone
			default:
				return spans, i, fmt.Errorf("expected ',' or ']' after an element, got %q", c)
			}
			i++
		case arrayDone:
			return spans, i, fmt.Errorf("data after the end of the array: %q", c)
		}
	}
	return spans, i, nil
}

// objectEnd returns the index after the '}' closing the object that starts at b[i],
// or -1 if b ends first. Strings are skipped with bytes.IndexByte, which is vectorized
// on arm64 and amd64; most bytes of a request are inside strings.
func objectEnd(b []byte, i int) int {
	depth := 0
	for i < len(b) {
		switch b[i] {
		case '"':
			start := i + 1
			j := start
			for {
				k := bytes.IndexByte(b[j:], '"')
				if k < 0 {
					return -1
				}
				q := j + k
				n := 0
				for p := q - 1; p >= start && b[p] == '\\'; p-- {
					n++
				}
				if n%2 == 0 { // not escaped
					i = q + 1
					break
				}
				j = q + 1
			}
			continue
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return -1
}
