package matcher

import (
	"fmt"
	"strconv"

	"github.com/go-faster/jx"
)

// Normalization: how a {method,url,headers,data} JSON object becomes the bytes the
// rules are matched against. The contract is normDescription; NormVersion is stored in
// the corpus manifest and checked when a corpus is opened.
//
// It is implemented three times, on purpose:
//   - jxObject below: the Go implementation, used by prepare (Convert) and by the jx
//     parser of the streaming mode;
//   - normalizeFileStd (normalize_std.go): encoding/json, a slow control;
//   - waap_sj_normalize (parser_simdjson_shim.cpp): simdjson, the fast streaming path.
//
// All of them end in the same layout, appendRequest here or its C++ copy, and must
// agree byte for byte: check-stream and TestStreamMatchesCorpus compare every parser
// with a prepared corpus.

const NormVersion = 1

const normDescription = "METHOD SP URL SP HTTP/1.1 CRLF, then 'Name: value CRLF' per header in JSON order and original case, CRLF, body. " +
	"JSON string escapes decoded; no percent-decoding, no case folding, body not truncated."

// appendRequest is the one normalization function. hdr is the already serialized header block.
func appendRequest[S string | []byte](dst []byte, method, url S, hdr []byte, body S) []byte {
	dst = append(dst, method...)
	dst = append(dst, ' ')
	dst = append(dst, url...)
	dst = append(dst, " HTTP/1.1\r\n"...)
	dst = append(dst, hdr...)
	dst = append(dst, "\r\n"...)
	return append(dst, body...)
}

// jxObject turns one {method,url,headers,data} object into a normalized request. Its
// four field buffers and the callbacks are allocated once and reused for every object.
// Scalars are written the way normalizeFileStd writes them: numbers as their JSON text,
// booleans as true/false, null and nested values as empty.
type jxObject struct {
	method, url, hdr, body []byte
	header, field          func(*jx.Decoder, []byte) error
}

func newJxObject() *jxObject {
	o := &jxObject{}
	o.header = func(d *jx.Decoder, name []byte) error {
		o.hdr = append(o.hdr, name...)
		o.hdr = append(o.hdr, ": "...)
		var err error
		if o.hdr, err = jxScalar(d, o.hdr); err != nil {
			return err
		}
		o.hdr = append(o.hdr, "\r\n"...)
		return nil
	}
	o.field = func(d *jx.Decoder, key []byte) error {
		var err error
		switch string(key) { // no allocation: the compiler compares bytes in place
		case "method":
			o.method, err = jxScalar(d, o.method[:0])
		case "url":
			o.url, err = jxScalar(d, o.url[:0])
		case "data":
			o.body, err = jxScalar(d, o.body[:0])
		case "headers":
			switch t := d.Next(); t {
			case jx.Object:
				err = d.ObjBytes(o.header)
			case jx.Null:
				err = d.Null()
			default:
				err = fmt.Errorf("headers must be an object or null, got %v", t)
			}
		default:
			err = d.Skip()
		}
		return err
	}
	return o
}

// decode reads the object d is positioned at and appends the normalized request to dst.
func (o *jxObject) decode(d *jx.Decoder, dst []byte) ([]byte, error) {
	o.method, o.url, o.hdr, o.body = o.method[:0], o.url[:0], o.hdr[:0], o.body[:0]
	if err := d.ObjBytes(o.field); err != nil {
		return dst, err
	}
	return appendRequest(dst, o.method, o.url, o.hdr, o.body), nil
}

func jxScalar(d *jx.Decoder, dst []byte) ([]byte, error) {
	switch d.Next() {
	case jx.String:
		return d.StrAppend(dst)
	case jx.Number:
		n, err := d.Num()
		return append(dst, n...), err
	case jx.Bool:
		v, err := d.Bool()
		return strconv.AppendBool(dst, v), err
	case jx.Null:
		return dst, d.Null()
	default: // nested value where a scalar was expected: skip, treat as empty
		return dst, d.Skip()
	}
}
