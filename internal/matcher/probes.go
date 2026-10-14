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
	Re        *regexp.Regexp
	Err       string // compile error category for unsupported patterns
}

// Rules is the parsed file. Patterns holds only what the Go regexp engine compiled;
// Unsupported is reported, never silently dropped.
type Rules struct {
	Patterns    []*Pattern
	Unsupported []*Pattern
	Services    []string // ServiceID -> name
	Probes      int
	BadLines    []string // match lines the minimal grammar could not parse
}

// LoadRules parses Probe/match/softmatch lines. Everything after the regex and its flags
// (p/../ v/../ cpe:..) is ignored: the task only needs service names.
func LoadRules(path string) (*Rules, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := &Rules{}
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
		// The source is handed to Go's regexp unchanged apart from the two nmap flags.
		// No PCRE->RE2 rewriting: what does not compile is unsupported.
		expr := p.Source
		if p.Flags != "" {
			expr = "(?" + p.Flags + ")" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			p.Err = errCategory(err, p.Source)
			r.Unsupported = append(r.Unsupported, p)
			continue
		}
		p.Re = re
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
	fmt.Fprintf(&b, "rules: %d match/softmatch lines in %d probes, %d services; %d compiled by Go regexp (%d match, %d softmatch; flag i %d, flag s %d), %d unsupported (%.1f%%), %d unparsed lines\n",
		total, r.Probes, len(r.Services), len(r.Patterns), hard, soft, fi, fs,
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
