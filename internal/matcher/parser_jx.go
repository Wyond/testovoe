package matcher

import (
	"errors"

	"github.com/go-faster/jx"
)

// jxParser is the pure-Go parser of the streaming mode and the control for simdjson.
// The object itself is decoded by jxObject, the same code Convert uses.
type jxParser struct {
	d    *jx.Decoder
	obj  *jxObject
	msgs int64
}

func newJxParser() *jxParser { return &jxParser{d: jx.DecodeBytes(nil), obj: newJxObject()} }

func (p *jxParser) stats() ParserStats { return ParserStats{Primary: "jx", PrimaryMsgs: p.msgs} }

func (p *jxParser) normalize(msg, dst []byte) ([]byte, error) {
	p.msgs++
	p.d.ResetBytes(msg)
	if p.d.Next() != jx.Object {
		return dst, errors.New("array element is not a JSON object")
	}
	return p.obj.decode(p.d, dst)
}

func (p *jxParser) trim() {
	if cap(p.obj.body) > maxKeptBuffer {
		p.obj = newJxObject()
	}
}
