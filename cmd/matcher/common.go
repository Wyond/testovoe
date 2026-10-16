package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"waap-matcher/internal/matcher"
)

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
