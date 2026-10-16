package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"syscall"
	"time"

	"waap-matcher/internal/matcher"
)

func prepare(args []string) {
	fs := flag.NewFlagSet("prepare", flag.ExitOnError)
	out := fs.String("out", "data/corpus", "output directory")
	workers := fs.Int("workers", runtime.NumCPU(), "files decoded in parallel")
	decoder := fs.String("decoder", "jx", "JSON decoder: jx (streaming), jxbytes (whole file in memory) or std (encoding/json)")
	inflight := fs.Int64("inflight-mb", 1024, "JSON megabytes decoded ahead of the writer")
	fs.Parse(args)
	if fs.NArg() == 0 {
		log.Fatal("usage: matcher prepare [-out dir] <json dir>...")
	}
	m, err := matcher.Convert(fs.Args(), *out, *workers, *decoder, *inflight<<20)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("conversion: %d files, %.0f MB JSON -> %d requests, %.0f MB normalized (avg %.0f B) in %.2fs with %d workers\n",
		len(m.Files), float64(m.InputBytes)/1e6, m.Requests, float64(m.PayloadBytes)/1e6,
		float64(m.PayloadBytes)/float64(max(m.Requests, 1)), m.ConvertSec, m.Workers)
	fmt.Printf("decoder %s: %d heap allocations (%.1f per request), %.0f MB allocated, %d GC cycles\n",
		m.Decoder, m.Allocs, float64(m.Allocs)/float64(max(m.Requests, 1)), float64(m.AllocBytes)/1e6, m.NumGC)
	fmt.Printf("writer waited %.2fs for decoded files and spent %.2fs writing; slowest single file took %.2fs to decode\n",
		m.WriterWaitSec, m.WriterWriteSec, m.LongestFileSec)
}

func run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	c := commonFlags(fs)
	mode := fs.String("mode", "fast", "naive or fast")
	workers := fs.Int("workers", runtime.NumCPU(), "worker goroutines (also GOMAXPROCS)")
	sample := fs.Int("sample", 0, "process only this many requests, spread evenly over the corpus (0 = all)")
	batch := fs.Int("batch", 256, "request ids claimed at once")
	access := fs.String("access", "mmap", "how workers read requests: mmap, or pread (copy each batch into a worker buffer)")
	outPath := fs.String("out", "results/out.jsonl", "result file (JSONL, arbitrary order); empty = format but do not write")
	metrics := fs.String("metrics", "", "append the run's metrics as one JSON line to this file")
	label := fs.String("label", "", "free-form label stored with the metrics")
	cpuProf := fs.String("cpuprofile", "", "write a CPU profile of the matching phase")
	fs.Parse(args)

	m, s, initSec := c.open()
	defer s.Close()
	cfg := matcher.Config{Mode: *mode, Workers: *workers, Sample: *sample, Batch: *batch, Access: *access}
	var outF *os.File
	if *outPath != "" {
		var err error
		if outF, err = os.Create(*outPath); err != nil {
			log.Fatal(err)
		}
		cfg.Out = outF
	}
	if *cpuProf != "" {
		f, err := os.Create(*cpuProf)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
	}
	res, err := matcher.Run(m, s, cfg)
	pprof.StopCPUProfile()
	if err != nil {
		log.Fatal(err)
	}
	if outF != nil {
		if err := outF.Close(); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Println(line(res))
	if res.Duplicates != 0 {
		log.Fatalf("%d requests were processed twice", res.Duplicates)
	}
	if *metrics != "" {
		var ru syscall.Rusage
		syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		rec := struct {
			*matcher.Result
			Label    string  `json:"label,omitempty"`
			Sample   int     `json:"sample"`
			Batch    int     `json:"batch"`
			InitSec  float64 `json:"rule_init_seconds"`
			MaxRSS   int64   `json:"max_rss_raw"` // bytes on macOS, KiB on Linux
			HeapSys  uint64  `json:"go_heap_sys_bytes"`
			NumGC    uint32  `json:"num_gc"`
			GoVer    string  `json:"go"`
			Time     string  `json:"time"`
			Compiled int     `json:"patterns"`
		}{res, *label, *sample, *batch, initSec, ru.Maxrss, ms.HeapSys, ms.NumGC, runtime.Version(),
			time.Now().Format(time.RFC3339), len(m.Rules.Patterns)}
		f, err := os.OpenFile(*metrics, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatal(err)
		}
		json.NewEncoder(f).Encode(rec)
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}
}

// check: naive vs fast on a sample, and fast with 1 worker vs N workers. Compares the
// full output line of every request, not match counts.
func check(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	c := commonFlags(fs)
	sample := fs.Int("sample", 20000, "requests for the naive vs fast comparison (0 = all)")
	workers := fs.Int("workers", runtime.NumCPU(), "workers for the parallel runs")
	full := fs.Bool("full", false, "also compare fast 1 worker vs N workers on the whole corpus")
	fs.Parse(args)
	m, s, _ := c.open()
	defer s.Close()

	must := func(cfg matcher.Config) *matcher.Result {
		r, err := matcher.Run(m, s, cfg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(line(r))
		if r.Duplicates != 0 {
			log.Fatalf("FAIL: %d requests processed twice", r.Duplicates)
		}
		return r
	}
	ok := true
	cmp := func(what string, a, b *matcher.Result) {
		differ, missing := matcher.Diff(a, b)
		if len(differ) == 0 && missing == 0 {
			fmt.Printf("OK   %s: %d requests, identical output lines, none missing or duplicated\n", what, len(a.Hashes))
			return
		}
		ok = false
		fmt.Printf("FAIL %s: %d differ, %d missing; first differing sample positions %v\n", what, len(differ), missing, differ[:min(len(differ), 10)])
	}
	// Naive is the reference; running it on N workers only makes the check finish sooner.
	naive := must(matcher.Config{Mode: "naive", Workers: *workers, Sample: *sample})
	fast1 := must(matcher.Config{Mode: "fast", Workers: 1, Sample: *sample})
	fastN := must(matcher.Config{Mode: "fast", Workers: *workers, Sample: *sample, Batch: 7})
	cmp("naive vs fast", naive, fast1)
	cmp(fmt.Sprintf("fast 1 worker vs %d workers", *workers), fast1, fastN)
	if *full {
		a := must(matcher.Config{Mode: "fast", Workers: 1, Access: "mmap"})
		b := must(matcher.Config{Mode: "fast", Workers: *workers, Access: "pread"})
		cmp("whole corpus, fast 1 worker mmap vs N workers pread", a, b)
	}
	if !ok {
		os.Exit(1)
	}
}
