// matcher: prepare a binary corpus from JSON, run the naive or prefiltered matcher over
// it, and check that both agree.
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
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"waap-matcher/internal/matcher"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: matcher stream|check-stream|prepare|run|check|calibrate|stats|summary [flags]")
	}
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "prepare":
		prepare(args)
	case "run":
		run(args)
	case "check":
		check(args)
	case "summary":
		summary(args)
	case "stream":
		stream(args)
	case "check-stream":
		checkStream(args)
	case "calibrate":
		calibrate(args)
	case "stats":
		fs := flag.NewFlagSet("stats", flag.ExitOnError)
		c := commonFlags(fs)
		fs.Parse(args)
		m, s, _ := c.open()
		defer s.Close()
		fmt.Print(matcher.SizeProfile(m, s))
	default:
		log.Fatalf("unknown command %q", cmd)
	}
}

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

type common struct {
	corpus, probes             *string
	engine, excluded, backends *string
}

func commonFlags(fs *flag.FlagSet) common {
	return common{
		corpus:   fs.String("corpus", "data/corpus", "directory written by prepare"),
		probes:   fs.String("probes", "data/nmap-service-probes", "nmap-service-probes file"),
		engine:   fs.String("engine", "go", "confirming engine for every rule: "+strings.Join(matcher.EngineNames(), ", ")),
		excluded: fs.String("excluded", "", "engine for the rules Go cannot compile (pcre2); empty leaves them out"),
		backends: fs.String("backends", "", "JSON {\"line\": \"engine\"} from `matcher calibrate`, overriding -engine per rule"),
	}
}

// rules loads and compiles the rules with the engine flags and prints the reports.
func (c common) rules() *matcher.Matcher {
	m, _ := c.load()
	return m
}

func (c common) open() (*matcher.Matcher, *matcher.Store, float64) {
	m, init := c.load()
	s, err := matcher.OpenStore(*c.corpus)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("corpus: %d requests, %.0f MB normalized; rule initialization %.2fs\n",
		s.Count(), float64(s.Manifest.PayloadBytes)/1e6, init)
	return m, s, init
}

func (c common) load() (*matcher.Matcher, float64) {
	t := time.Now()
	opt := matcher.Options{Engine: *c.engine, Excluded: *c.excluded}
	if *c.backends != "" {
		b, err := os.ReadFile(*c.backends)
		if err != nil {
			log.Fatal(err)
		}
		var per map[string]string
		if err := json.Unmarshal(b, &per); err != nil {
			log.Fatalf("%s: %v", *c.backends, err)
		}
		opt.PerLine = map[int]string{}
		for k, v := range per {
			n, err := strconv.Atoi(k)
			if err != nil {
				log.Fatalf("%s: line %q", *c.backends, k)
			}
			opt.PerLine[n] = v
		}
	}
	rules, err := matcher.LoadRules(*c.probes, opt)
	if err != nil {
		log.Fatal(err)
	}
	m := matcher.NewMatcher(rules)
	init := time.Since(t).Seconds()
	fmt.Print(rules.Report(), m.Filter.Report())
	return m, init
}

func line(r *matcher.Result) string {
	return fmt.Sprintf("%-5s %-5s workers=%-2d  %9d req  %8.3fs  %10.0f req/s  %8.1f MB/s  %9.2f regex calls/req  %d requests with a match",
		r.Mode, r.Access, r.Workers, r.Requests, r.Seconds, r.ReqPerSec, r.MBPerSec, r.RegexCalls, r.WithMatch)
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

// summary prints the median of repeated runs from a metrics file written by `run -metrics`.
func summary(args []string) {
	if len(args) < 1 {
		log.Fatal("usage: matcher summary <metrics.jsonl> [corpus dir]")
	}
	if len(args) > 1 {
		if s, err := matcher.OpenStore(args[1]); err == nil {
			m := s.Manifest
			fmt.Printf("conversion (JSON decode + normalization + write, %d workers): %.2fs for %d requests, %.0f MB JSON -> %.0f MB normalized\n\n",
				m.Workers, m.ConvertSec, m.Requests, float64(m.InputBytes)/1e6, float64(m.PayloadBytes)/1e6)
			s.Close()
		}
	}
	f, err := os.Open(args[0])
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	type rec struct {
		Label    string  `json:"label"`
		Mode     string  `json:"mode"`
		Workers  int     `json:"workers"`
		Requests int64   `json:"requests"`
		Seconds  float64 `json:"matching_with_output_seconds"`
		Bytes    int64   `json:"payload_bytes"`
	}
	type key struct {
		label, mode string
		workers     int
		requests    int64
	}
	groups := map[key][]float64{}
	bytes := map[key]int64{}
	var order []key
	dec := json.NewDecoder(f)
	for dec.More() {
		var r rec
		if err := dec.Decode(&r); err != nil {
			log.Fatal(err)
		}
		k := key{r.Label, r.Mode, r.Workers, r.Requests}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r.Seconds)
		bytes[k] = r.Bytes
	}
	base := map[string]float64{} // label+mode+requests -> median seconds of the 1-worker run
	med := func(k key) float64 {
		v := append([]float64(nil), groups[k]...)
		sort.Float64s(v)
		return v[len(v)/2]
	}
	for _, k := range order {
		if k.workers == 1 {
			base[fmt.Sprint(k.label, k.mode, k.requests)] = med(k)
		}
	}
	fmt.Println("| label | mode | workers | requests | runs | median s | min s | max s | req/s | MB/s | speedup | efficiency |")
	fmt.Println("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
	for _, k := range order {
		v := append([]float64(nil), groups[k]...)
		sort.Float64s(v)
		m := med(k)
		sp := "- | -"
		if b, ok := base[fmt.Sprint(k.label, k.mode, k.requests)]; ok {
			sp = fmt.Sprintf("%.2fx | %.0f%%", b/m, 100*b/m/float64(k.workers))
		}
		fmt.Printf("| %s | %s | %d | %d | %d | %.3f | %.3f | %.3f | %.0f | %.0f | %s |\n",
			k.label, k.mode, k.workers, k.requests, len(v), m, v[0], v[len(v)-1],
			float64(k.requests)/m, float64(bytes[k])/1e6/m, sp)
	}
	// naive vs fast on the same sample, both single-threaded
	for _, k := range order {
		if k.mode != "naive" || k.workers != 1 {
			continue
		}
		if f := (key{k.label, "fast", 1, k.requests}); len(groups[f]) > 0 {
			fmt.Printf("\nprefilter vs naive, 1 worker, same %d requests: %.2fs vs %.2fs = %.0fx\n", k.requests, med(f), med(k), med(k)/med(f))
		}
	}
}

// calibrate measures every candidate rule on every listed engine and writes the per-rule
// choice that `run -backends` reads.
func calibrate(args []string) {
	fs := flag.NewFlagSet("calibrate", flag.ExitOnError)
	c := commonFlags(fs)
	names := fs.String("engines", strings.Join(matcher.EngineNames(), ","), "engines to compare")
	sample := fs.Int("sample", 50000, "requests to calibrate on")
	offset := fs.Int("offset", 1, "first request; the baseline sample starts at 0, so 1 keeps them disjoint")
	out := fs.String("out", "results/backends.json", "per-rule engine choice, by line number")
	fs.Parse(args)
	m, s, _ := c.open()
	defer s.Close()
	list := strings.Split(*names, ",")
	t := time.Now()
	rows, choice, err := matcher.Calibrate(m, s, list, *sample, *offset)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("calibrated %d rules on %d requests in %.1fs; %d rules move off Go\n\n", len(rows), *sample, time.Since(t).Seconds(), len(choice))
	fmt.Print(matcher.CalibrationReport(rows, list, 25))
	per := map[string]string{}
	count := map[string]int{}
	for line, e := range choice {
		per[strconv.Itoa(line)] = e
		count[e]++
	}
	fmt.Printf("\nchosen: %v\n", count)
	b, _ := json.MarshalIndent(per, "", " ")
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		log.Fatal(err)
	}
}

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
	cfg := matcher.StreamConfig{Mode: *mode, Parser: *parser, Workers: *workers, ChunkSize: *chunk, QueueBytes: *queueMB << 20}
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
	fmt.Printf("stream %-8s workers=%-2d %9d req  %8.3fs  %9.0f req/s  %7.0f MB/s JSON  %6.2f regex calls/req  alloc %.0f MB (%.1f allocs/req)  GC %d  peak RSS %.2f GB  fallbacks %d  read %.2fs (stalled %.2fs), split %.2fs, queue full %.2fs; workers idle %.2fs total\n",
		*parser, *workers, r.Requests, r.Seconds, r.ReqPerSec, r.MBPerSec, r.RegexCalls, float64(r.AllocBytes)/1e6,
		float64(r.Allocs)/float64(max(r.Requests, 1)), r.NumGC, float64(ru.Maxrss)/(1<<30), r.Fallbacks,
		r.ReadSec, r.ReadStallSec, r.SplitSec, r.ReaderWaitSec, r.WorkerIdleSec)
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
