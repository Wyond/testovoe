package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"waap-matcher/internal/matcher"
)

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
		Readers  int     `json:"Readers"` // streaming runs only
	}
	type key struct {
		label, mode      string
		workers, readers int
		requests         int64
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
		k := key{r.Label, r.Mode, r.Workers, r.Readers, r.Requests}
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
	fmt.Println("| label | mode | workers | readers | requests | runs | median s | min s | max s | req/s | MB/s | speedup | efficiency |")
	fmt.Println("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
	for _, k := range order {
		v := append([]float64(nil), groups[k]...)
		sort.Float64s(v)
		m := med(k)
		sp := "- | -"
		if b, ok := base[fmt.Sprint(k.label, k.mode, k.requests)]; ok {
			sp = fmt.Sprintf("%.2fx | %.0f%%", b/m, 100*b/m/float64(k.workers))
		}
		readers := "-"
		if k.readers > 0 {
			readers = strconv.Itoa(k.readers)
		}
		fmt.Printf("| %s | %s | %d | %s | %d | %d | %.3f | %.3f | %.3f | %.0f | %.0f | %s |\n",
			k.label, k.mode, k.workers, readers, k.requests, len(v), m, v[0], v[len(v)-1],
			float64(k.requests)/m, float64(bytes[k])/1e6/m, sp)
	}
	// naive vs fast on the same sample, both single-threaded
	for _, k := range order {
		if k.mode != "naive" || k.workers != 1 {
			continue
		}
		if f := (key{k.label, "fast", 1, k.readers, k.requests}); len(groups[f]) > 0 {
			fmt.Printf("\nprefilter vs naive, 1 worker, same %d requests: %.2fs vs %.2fs = %.0fx\n", k.requests, med(f), med(k), med(k)/med(f))
		}
	}
}

// stats prints the distribution of request sizes and where the matching time goes by size.
func stats(args []string) {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	c := commonFlags(fs)
	fs.Parse(args)
	m, s, _ := c.open()
	defer s.Close()
	fmt.Print(matcher.SizeProfile(m, s))
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
