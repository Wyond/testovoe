package matcher

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// The control decoder: encoding/json, one token at a time. It is the slowest of the
// three normalizations and is kept only to check the others and to compare speed
// (prepare -decoder std, docs/EXPERIMENTS.md E14). Nothing in the main path uses it.

// normalizeFileStd streams one JSON array of {method,url,headers,data} objects with
// encoding/json and returns the normalized requests back to back plus the end offset of
// each. Every token comes back as a freshly allocated string. Kept for comparison with
// normalizeFileJx, see docs/EXPERIMENTS.md E14.
func normalizeFileStd(path string) (buf []byte, ends []int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(bufio.NewReaderSize(f, 1<<20))
	dec.UseNumber()

	scalar := func() (string, error) {
		t, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch v := t.(type) {
		case string:
			return v, nil
		case json.Number:
			return v.String(), nil
		case bool:
			return fmt.Sprint(v), nil
		case json.Delim: // nested value where a scalar was expected: skip, treat as empty
			for depth := 1; depth > 0; {
				t, err := dec.Token()
				if err != nil {
					return "", err
				}
				if d, ok := t.(json.Delim); ok {
					if d == '{' || d == '[' {
						depth++
					} else {
						depth--
					}
				}
			}
		}
		return "", nil // null
	}

	var hdr []byte
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return nil, nil, fmt.Errorf("expected a JSON array: %v", err)
	}
	for dec.More() {
		if t, err := dec.Token(); err != nil || t != json.Delim('{') {
			return nil, nil, fmt.Errorf("expected an object: %v", err)
		}
		var method, url, body string
		hdr = hdr[:0]
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, nil, err
			}
			switch key, _ := kt.(string); key {
			case "method":
				method, err = scalar()
			case "url":
				url, err = scalar()
			case "data":
				body, err = scalar()
			case "headers":
				var t json.Token
				if t, err = dec.Token(); err == nil && t == json.Delim('{') {
					for dec.More() {
						k, kerr := dec.Token()
						if kerr != nil {
							return nil, nil, kerr
						}
						v, verr := scalar()
						if verr != nil {
							return nil, nil, verr
						}
						name, _ := k.(string)
						hdr = append(hdr, name...)
						hdr = append(hdr, ": "...)
						hdr = append(hdr, v...)
						hdr = append(hdr, "\r\n"...)
					}
					_, err = dec.Token() // }
				} else if err == nil && t != nil {
					err = fmt.Errorf("headers must be an object or null, got %v", t)
				}
			default:
				_, err = scalar()
			}
			if err != nil {
				return nil, nil, err
			}
		}
		if _, err := dec.Token(); err != nil { // }
			return nil, nil, err
		}
		buf = appendRequest(buf, method, url, hdr, body)
		ends = append(ends, len(buf))
	}
	if _, err := dec.Token(); err != nil { // ]
		return nil, nil, err
	}
	return buf, ends, nil
}
