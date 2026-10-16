// matcher: prepare a binary corpus from JSON, run the naive or prefiltered matcher over
// it, and check that both agree. Commands, by file:
//
//	stream.go   stream, check-stream: the end-to-end mode on the JSON files
//	offline.go  prepare, run, check: the binary corpus and the matcher on it
//	report.go   summary, stats, calibrate
//	common.go   flags and loading shared by all of them
package main

import (
	"log"
	"os"
)

// extraCommands are commands that exist only with some build tags.
var extraCommands = map[string]func([]string){}

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
		stats(args)
	default:
		if f, ok := extraCommands[cmd]; ok {
			f(args)
			return
		}
		log.Fatalf("unknown command %q", cmd)
	}
}
