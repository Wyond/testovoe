package matcher

import (
	"os"
	"strings"
	"testing"
)

// benchMessages splits the BENCH_JSON files (default: a few corpus files) into messages,
// each followed by jsonPadding bytes of capacity.
func benchMessages(b *testing.B) [][]byte {
	files := strings.Split(os.Getenv("BENCH_JSON"), ",")
	if files[0] == "" {
		files = []string{
			"/Users/amir/Downloads/Legitimate/browsing_2024_amazon_hl.json",
			"/Users/amir/Downloads/Legitimate/browsing_2024_adobe_hl.json",
			"/Users/amir/Downloads/Malicious/xss.json",
		}
	}
	var msgs [][]byte
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
		}
	}
	return msgs
}

// Per-message parse + normalize cost of each JSON parser, without matching:
//
//	go test -tags simdjson ./internal/matcher -run XXX -bench ParseMessage -benchmem
//
// BENCH_JSON (comma-separated files) chooses the messages; by default a few corpus files.
func BenchmarkParseMessage(b *testing.B) {
	msgs := benchMessages(b)
	var total int64
	for _, m := range msgs {
		total += int64(len(m))
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

// Cost of finding element boundaries alone, on files already in memory:
//
//	go test ./internal/matcher -run XXX -bench SplitElements
func BenchmarkSplitElements(b *testing.B) {
	files := strings.Split(os.Getenv("BENCH_JSON"), ",")
	if files[0] == "" {
		files = []string{"/Users/amir/Downloads/Legitimate/browsing_2024_amazon_hl.json", "/Users/amir/Downloads/Legitimate/browsing_2024_tiktok_mu.json"}
	}
	var data [][]byte
	var total int64
	for _, f := range files {
		d, err := os.ReadFile(f)
		if err != nil {
			b.Skip(err)
		}
		data = append(data, d)
		total += int64(len(d))
	}
	b.SetBytes(total)
	var spans []span
	for i := 0; i < b.N; i++ {
		for _, d := range data {
			st := expectOpen
			var err error
			if spans, _, err = splitElements(d, &st, spans[:0]); err != nil || st != arrayDone {
				b.Fatal(err)
			}
		}
	}
}
