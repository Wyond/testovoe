package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"waap-matcher/internal/matcher"
)

// stream is the end-to-end mode: the JSON files are read and parsed on every run.
func stream(args []string) {
	fs := flag.NewFlagSet("stream", flag.ExitOnError)
	c := commonFlags(fs)
	parser := fs.String("parser", "jx", "JSON parser: "+strings.Join(matcher.ParserNames(), ", "))
	mode := fs.String("mode", "fast", "naive or fast")
	workers := fs.Int("workers", runtime.NumCPU(), "worker goroutines (also GOMAXPROCS)")
	chunk := fs.Int("chunk", 1<<20, "bytes read per chunk")
	queueMB := fs.Int64("queue-mb", 256, "JSON megabytes queued or in progress (backpressure above)")
	outPath := fs.String("out", "results/out.jsonl", "result file; empty = format but do not write")
	metrics := fs.String("metrics", "", "append the run's metrics as one JSON line to this file")
	label := fs.String("label", "", "free-form label stored with the metrics")
	cpuProf := fs.String("cpuprofile", "", "write a CPU profile")
	memProf := fs.String("memprofile", "", "write an allocation profile (every allocation sampled)")
	splitOnly := fs.Bool("split-only", false, "only read the files and find element boundaries (cost of message splitting)")
	readers := fs.Int("readers", 1, "files read and split in parallel (each file in order, like a partition with one consumer)")
	fs.Parse(args)
	if fs.NArg() == 0 {
		log.Fatal("usage: matcher stream [flags] <json dir>...")
	}
	paths, err := matcher.InputFiles(fs.Args())
	if err != nil {
		log.Fatal(err)
	}
	t := time.Now()
	m := c.rules()
	initSec := time.Since(t).Seconds()
	fmt.Printf("parser %s: %s; %d files; rule initialization %.2fs\n", *parser, matcher.ParserBackend(*parser), len(paths), initSec)
	cfg := matcher.StreamConfig{Mode: *mode, Parser: *parser, Workers: *workers, ChunkSize: *chunk, QueueBytes: *queueMB << 20, SplitOnly: *splitOnly, Readers: *readers}
	var outF *os.File
	if *outPath != "" {
		if outF, err = os.Create(*outPath); err != nil {
			log.Fatal(err)
		}
		cfg.Out = outF
	}
	if *memProf != "" {
		runtime.MemProfileRate = 1
	}
	if *cpuProf != "" {
		f, err := os.Create(*cpuProf)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
	}
	r, err := matcher.RunStream(m, paths, cfg)
	pprof.StopCPUProfile()
	if err != nil {
		log.Fatal(err)
	}
	if outF != nil {
		if err := outF.Close(); err != nil {
			log.Fatal(err)
		}
	}
	if *memProf != "" {
		f, err := os.Create(*memProf)
		if err != nil {
			log.Fatal(err)
		}
		pprof.Lookup("allocs").WriteTo(f, 0)
		f.Close()
	}
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	if r.SplitOnly {
		fmt.Printf("split-only readers=%d workers=%-2d %9d messages  %8.3fs  %9.0f msg/s  %7.0f MB/s JSON  read %.2fs (stalled %.2fs), split %.2fs, queue full %.2fs\n",
			r.Readers, *workers, r.Requests, r.Seconds, r.ReqPerSec, r.MBPerSec, r.ReadSec, r.ReadStallSec, r.SplitSec, r.ReaderWaitSec)
		return
	}
	ps := r.Parse
	fmt.Printf("stream %-8s readers=%d workers=%-2d %9d req  %8.3fs  %9.0f req/s  %7.0f MB/s JSON  %6.2f regex calls/req  Go alloc %.0f MB (%.2f allocs/req)  GC %d  peak RSS %.2f GB\n",
		*parser, r.Readers, *workers, r.Requests, r.Seconds, r.ReqPerSec, r.MBPerSec, r.RegexCalls, float64(r.AllocBytes)/1e6,
		float64(r.Allocs)/float64(max(r.Requests, 1)), r.NumGC, float64(ru.Maxrss)/(1<<30))
	fmt.Printf("       parsed by %s: %d, fallback to jx: %d %v; C++ buffer growths %d (%.0f MB, not in Go alloc); read %.2fs (stalled %.2fs), split %.2fs, queue full %.2fs; workers idle %.2fs total\n",
		ps.Primary, ps.PrimaryMsgs, ps.FallbackMsgs, ps.Reasons, ps.NativeGrowths, float64(ps.NativeGrowthBytes)/1e6,
		r.ReadSec, r.ReadStallSec, r.SplitSec, r.ReaderWaitSec, r.WorkerIdleSec)
	fmt.Printf("       worker time, summed over workers: JSON parse+normalize %.2fs, prefilter+regex %.2fs, result formatting %.2fs, hand-over %.2fs; writer (ids, hash, write) %.2fs\n",
		r.ParseSec, r.MatchSec, r.FormatSec, r.WriteSec, r.WriterSec)
	if ps.PrimaryMsgs+ps.FallbackMsgs != r.Requests {
		log.Fatalf("parser counters cover %d messages, %d were processed", ps.PrimaryMsgs+ps.FallbackMsgs, r.Requests)
	}
	if *metrics != "" {
		rec := struct {
			*matcher.StreamResult
			Label   string  `json:"label,omitempty"`
			InitSec float64 `json:"rule_init_seconds"`
			MaxRSS  int64   `json:"max_rss_raw"`
			GoVer   string  `json:"go"`
			Time    string  `json:"time"`
		}{r, *label, initSec, ru.Maxrss, runtime.Version(), time.Now().Format(time.RFC3339)}
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

// checkStream compares the normalized bytes a parser produces, request by request, with
// a prepared corpus.
func checkStream(args []string) {
	fs := flag.NewFlagSet("check-stream", flag.ExitOnError)
	corpus := fs.String("corpus", "data/corpus", "prepared corpus to compare with")
	parser := fs.String("parser", "jx", "JSON parser")
	fs.Parse(args)
	paths, err := matcher.InputFiles(fs.Args())
	if err != nil {
		log.Fatal(err)
	}
	s, err := matcher.OpenStore(*corpus)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	var n, bad int64
	err = matcher.StreamNormalized(paths, *parser, func(id int64, norm []byte) error {
		if int(id) >= s.Count() || !bytes.Equal(norm, s.Request(int(id))) {
			if bad++; bad <= 5 {
				fmt.Printf("  differs: request %d\n", id)
			}
		}
		n++
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	if bad == 0 && n == int64(s.Count()) {
		fmt.Printf("OK   %s: %d requests, normalized bytes identical to %s\n", *parser, n, *corpus)
		return
	}
	fmt.Printf("FAIL %s: %d requests (corpus has %d), %d differ\n", *parser, n, s.Count(), bad)
	os.Exit(1)
}
