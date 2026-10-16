//go:build pcre2

package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"
	"strings"

	"waap-matcher/internal/matcher"
)

func init() { extraCommands["oracle"] = oracle }

// oracle compares the matcher with every rule run by PCRE2 on bytes, as nmap runs them.
func oracle(args []string) {
	fs := flag.NewFlagSet("oracle", flag.ExitOnError)
	c := commonFlags(fs)
	sample := fs.Int("sample", 50000, "requests, spread evenly over the corpus; 0 = all")
	workers := fs.Int("workers", runtime.NumCPU(), "worker goroutines")
	top := fs.Int("top", 30, "rules listed")
	fs.Parse(args)
	m, s, _ := c.open()
	defer s.Close()
	n := s.Count()
	if *sample <= 0 || *sample > n {
		*sample = n
	}
	ids := make([]int, *sample)
	for i := range ids {
		ids[i] = int(int64(i) * int64(n) / int64(*sample))
	}
	r, err := matcher.Oracle(m, s, ids, *workers)
	if err != nil {
		log.Fatal(err)
	}
	pct := func(a int64) string { return fmt.Sprintf("%d (%.3f%%)", a, 100*float64(a)/float64(r.Requests)) }
	fmt.Printf("\nэталон: каждое правило скомпилировано PCRE2 в байтовом режиме (без UTF, только флаги i/s), без предфильтра; %.1f с\n", r.Seconds)
	fmt.Printf("запросов %d: с не-ASCII байтами %s, с невалидным UTF-8 %s; эталон упёрся в лимит перебора %d раз\n", r.Requests, pct(r.NonASCII), pct(r.InvalidUTF8), r.Inconclusive)
	fmt.Printf("совпадений правил: у нас %d, у эталона %d\n", r.Matches, r.RefMatches)
	fmt.Printf("запросов, где различаются сработавшие правила: %s; строка вывода: %s; первый hard-сервис: %s\n",
		pct(r.PatternDiff), pct(r.ServiceDiff), pct(r.HardDiff))
	fmt.Printf("правил с расхождением или с лимитом у эталона: %d из %d (при лимите правило в этом запросе не сравнивается)\n\n", len(r.Rules), len(m.Rules.Patterns))
	if len(r.Rules) == 0 {
		return
	}
	fmt.Println("| строка | проба | тип | сервис | наш движок | только у эталона (ASCII-запросы) | только у нас (ASCII-запросы) | лимит эталона: у нас есть / нет | пример id | правило |")
	fmt.Println("|---:|---|---|---|---|---:|---:|---:|---:|---|")
	for i, x := range r.Rules {
		if i == *top {
			break
		}
		kind := "match"
		if x.Kind == matcher.Soft {
			kind = "softmatch"
		}
		src := x.Source
		if len(src) > 70 {
			src = src[:70] + "…"
		}
		src = strings.ReplaceAll(src, "|", `\|`)
		fmt.Printf("| %d | %s | %s | %s | %s | %d (%d) | %d (%d) | %d / %d | %d | `%s` %s |\n",
			x.Line, x.Probe, kind, x.Service, x.Engine, x.Missed, x.MissedASCII, x.Extra, x.ExtraASCII, x.LimitOurs, x.LimitNone, x.Example, src, x.Flags)
	}
}
