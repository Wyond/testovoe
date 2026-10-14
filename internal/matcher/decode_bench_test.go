package matcher

import (
	"os"
	"testing"
)

func BenchmarkNormalize(b *testing.B) {
	path := os.Getenv("BENCH_FILE")
	if path == "" {
		b.Skip()
	}
	st, _ := os.Stat(path)
	for _, dec := range []string{"std", "jx", "jxbytes"} {
		b.Run(dec, func(b *testing.B) {
			b.SetBytes(st.Size())
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, _, err := decoders[dec](path); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
