// Package matcher matches normalized HTTP requests against nmap-service-probes rules.
package matcher

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
)

type Kind uint8

const (
	Hard Kind = iota // "match"
	Soft             // "softmatch"
)

// Pattern is one match/softmatch line. ID is the index among supported patterns in file
// order, which is also our priority order (Probe order, then line order).
type Pattern struct {
	ID        uint32
	Kind      Kind
	Service   string
	ServiceID uint32
	Probe     string // "TCP GetRequest"
	Line      int
	Source    string // regex exactly as in the file
	Flags     string // subset of "is"
	Re        Re
	Engine    string // engine that compiled Re
	// Analysis is the expression the prefilter analyses, in Go syntax. Normally the
	// pattern itself; for a rule recovered by a PCRE engine it is a relaxed version whose
	// language contains the rule's (see relax.go).
	Analysis  string
	Recovered bool   // Go cannot compile the rule; it runs on Options.Excluded
	Err       string // compile error category for unsupported patterns
}

// Options choose the confirming engine per rule.
type Options struct {
	Engine   string         // default engine ("go" if empty)
	PerLine  map[int]string // overrides by line number in the rule file (from calibrate)
	Excluded string         // engine for rules Go cannot compile; "" leaves them out
}

// Rules is the parsed file. Patterns holds only what the Go regexp engine compiled;
// Unsupported is reported, never silently dropped.
type Rules struct {
	Patterns    []*Pattern
	Unsupported []*Pattern
	Services    []string // ServiceID -> name
	Probes      int
	BadLines    []string // match lines the minimal grammar could not parse
	Options     Options
}

// LoadRules parses Probe/match/softmatch lines. Everything after the regex and its flags
// (p/../ v/../ cpe:..) is ignored: the task only needs service names.
func LoadRules(path string, opt Options) (*Rules, error) {
	if opt.Engine == "" {
		opt.Engine = "go"
	}
	for _, e := range append([]string{opt.Engine, opt.Excluded}, mapValues(opt.PerLine)...) {
		if e != "" && engines[e] == nil {
			return nil, fmt.Errorf("engine %q is not compiled into this binary (have %v)", e, EngineNames())
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := &Rules{Options: opt}
	svcID := map[string]uint32{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	probe, line := "", 0
	for sc.Scan() {
		line++
		l := sc.Bytes()
		var kind Kind
		switch {
		case bytes.HasPrefix(l, []byte("Probe ")):
			if fs := strings.Fields(string(l)); len(fs) >= 3 {
				probe = fs[1] + " " + fs[2]
				r.Probes++
			}
			continue
		case bytes.HasPrefix(l, []byte("match ")):
			kind = Hard
		case bytes.HasPrefix(l, []byte("softmatch ")):
			kind = Soft
		default:
			continue
		}
		p, err := parseMatch(l)
		if err != nil {
			r.BadLines = append(r.BadLines, fmt.Sprintf("line %d: %v", line, err))
			continue
		}
		p.Kind, p.Probe, p.Line = kind, probe, line
		if !jsonSafe(p.Service) {
			return nil, fmt.Errorf("line %d: service name %q is not plain ASCII, output writer would need escaping", line, p.Service)
		}
		id, ok := svcID[p.Service]
		if !ok {
			id = uint32(len(r.Services))
			svcID[p.Service] = id
			r.Services = append(r.Services, p.Service)
		}
		p.ServiceID = id
		// The source is handed over unchanged apart from the two nmap flags. No
		// PCRE->RE2 rewriting: a rule Go cannot compile is unsupported, unless an engine
		// that takes PCRE syntax is configured for those rules.
		expr := p.Source
		if p.Flags != "" {
			expr = "(?" + p.Flags + ")" + expr
		}
		if _, gerr := regexp.Compile(expr); gerr == nil {
			name := opt.Engine
			if e, ok := opt.PerLine[line]; ok {
				name = e
			}
			re, err := engines[name].Compile(expr)
			if err != nil {
				p.Err = name + ": " + strings.SplitN(err.Error(), "\n", 2)[0]
				r.Unsupported = append(r.Unsupported, p)
				continue
			}
			p.Re, p.Engine, p.Analysis = re, name, expr
		} else {
			p.Err = errCategory(gerr, p.Source)
			e := engines[opt.Excluded]
			if e == nil || e.CompilePCRE == nil {
				r.Unsupported = append(r.Unsupported, p)
				continue
			}
			re, err := e.CompilePCRE(p.Source, p.Flags)
			if err != nil {
				p.Err += "; " + e.Name + ": " + strings.SplitN(err.Error(), "\n", 2)[0]
				r.Unsupported = append(r.Unsupported, p)
				continue
			}
			p.Re, p.Engine, p.Recovered = re, e.Name, true
			p.Analysis = relaxPCRE(p.Source, p.Flags) // "" if it cannot be parsed: always a candidate
		}
		p.ID = uint32(len(r.Patterns))
		r.Patterns = append(r.Patterns, p)
	}
	return r, sc.Err()
}

// parseMatch handles `match <service> m<delim><regex><delim>[is]`. The nmap format has
// no escape for the delimiter, the author picks one that does not occur in the regex;
// we still verify that what follows the closing delimiter looks like flags.
func parseMatch(l []byte) (*Pattern, error) {
	rest := l[bytes.IndexByte(l, ' ')+1:]
	sp := bytes.IndexByte(rest, ' ')
	if sp <= 0 {
		return nil, errors.New("no service name")
	}
	p := &Pattern{Service: string(rest[:sp])}
	rest = bytes.TrimLeft(rest[sp:], " ")
	if len(rest) < 3 || rest[0] != 'm' {
		return nil, errors.New("no m<delim>")
	}
	delim := rest[1]
	end := bytes.IndexByte(rest[2:], delim)
	if end < 0 {
		return nil, errors.New("unterminated regex")
	}
	p.Source = string(rest[2 : 2+end])
	tail := rest[2+end+1:]
	i := 0
	for ; i < len(tail) && tail[i] != ' '; i++ {
		switch tail[i] {
		case 'i', 's':
			if !strings.Contains(p.Flags, string(tail[i])) {
				p.Flags += string(tail[i])
			}
		default:
			return nil, fmt.Errorf("unexpected %q after regex", tail[i])
		}
	}
	return p, nil
}

func jsonSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return s != ""
}

// errCategory gives every unsupported pattern exactly one primary reason.
func errCategory(err error, src string) string {
	var se *syntax.Error
	if !errors.As(err, &se) {
		return "other"
	}
	switch {
	case se.Code == syntax.ErrInvalidUTF8:
		return "raw non-UTF-8 byte in pattern"
	case strings.HasPrefix(se.Expr, "(?!"):
		return "negative lookahead (?!"
	case strings.HasPrefix(se.Expr, "(?="):
		return "lookahead (?="
	case strings.HasPrefix(se.Expr, "(?<"):
		return "lookbehind (?<"
	case strings.HasPrefix(se.Expr, "(?>"):
		return "atomic group (?>"
	case se.Code == syntax.ErrInvalidRepeatOp:
		return "possessive/nested quantifier"
	case se.Code == syntax.ErrInvalidRepeatSize:
		return "repeat count > 1000"
	case se.Code == syntax.ErrInvalidEscape:
		return "escape not in RE2 (backreference etc.)"
	}
	return string(se.Code)
}

// Report is the compile summary printed by every command.
func (r *Rules) Report() string {
	var b strings.Builder
	hard, soft, fi, fs := 0, 0, 0, 0
	for _, p := range r.Patterns {
		if p.Kind == Hard {
			hard++
		} else {
			soft++
		}
		if strings.Contains(p.Flags, "i") {
			fi++
		}
		if strings.Contains(p.Flags, "s") {
			fs++
		}
	}
	total := len(r.Patterns) + len(r.Unsupported)
	perEngine := map[string]int{}
	recovered := 0
	for _, p := range r.Patterns {
		perEngine[p.Engine]++
		if p.Recovered {
			recovered++
		}
	}
	fmt.Fprintf(&b, "engines %v (%d recovered from the Go-unsupported set by %q); rules: %d match/softmatch lines in %d probes, %d services; %d compiled by the engine (%d match, %d softmatch; flag i %d, flag s %d), %d unsupported (%.1f%%), %d unparsed lines\n",
		perEngine, recovered, r.Options.Excluded, total, r.Probes, len(r.Services), len(r.Patterns), hard, soft, fi, fs,
		len(r.Unsupported), 100*float64(len(r.Unsupported))/float64(max(total, 1)), len(r.BadLines))
	cat := map[string]int{}
	for _, p := range r.Unsupported {
		cat[p.Err]++
	}
	keys := make([]string, 0, len(cat))
	for k := range cat {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(a, c int) bool {
		return cat[keys[a]] > cat[keys[c]] || cat[keys[a]] == cat[keys[c]] && keys[a] < keys[c]
	})
	for _, k := range keys {
		fmt.Fprintf(&b, "  unsupported %5d  %s\n", cat[k], k)
	}
	for _, l := range r.BadLines {
		fmt.Fprintf(&b, "  unparsed %s\n", l)
	}
	return b.String()
}

func mapValues(m map[int]string) []string {
	var v []string
	for _, x := range m {
		v = append(v, x)
	}
	return v
}

// Label names the engine configuration in reports and metrics.
func (r *Rules) Label() string {
	l := r.Options.Engine
	if len(r.Options.PerLine) > 0 {
		l += fmt.Sprintf("+%d-overrides", len(r.Options.PerLine))
	}
	if r.Options.Excluded != "" {
		l += "+excluded:" + r.Options.Excluded
	}
	return l
}
