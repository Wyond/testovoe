package matcher

import (
	"os"
	"strings"
	"testing"
)

// Per-message parse + normalize cost of each JSON parser, without matching:
//
//	go test -tags simdjson ./internal/matcher -run XXX -bench ParseMessage -benchmem
//
// BENCH_JSON (comma-separated files) chooses the messages; by default a few corpus files.
func BenchmarkParseMessage(b *testing.B) {
	files := strings.Split(os.Getenv("BENCH_JSON"), ",")
	if files[0] == "" {
		files = []string{
			"/Users/amir/Downloads/Legitimate/browsing_2024_amazon_hl.json",
			"/Users/amir/Downloads/Legitimate/browsing_2024_adobe_hl.json",
			"/Users/amir/Downloads/Malicious/xss.json",
		}
	}
	var msgs [][]byte
	var total int64
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			b.Skip(err)
		}
		padded := append(data, make([]byte, jsonPadding)...)[:len(data)]
		st := expectOpen
		spans, _, err := splitElements(padded, &st, nil)
		if err != nil {
			b.Fatal(err)
		}
		for _, sp := range spans {
			msgs = append(msgs, padded[sp.start:sp.end])
			total += int64(sp.end - sp.start)
		}
	}
	for _, name := range ParserNames() {
		b.Run(name, func(b *testing.B) {
			p, err := parsers[name].New()
			if err != nil {
				b.Fatal(err)
			}
			dst := make([]byte, 0, 64<<10)
			for _, m := range msgs { // warm up buffers
				dst, _ = p.normalize(m, dst[:0])
			}
			b.SetBytes(total / int64(len(msgs)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if dst, err = p.normalize(msgs[i%len(msgs)], dst[:0]); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
