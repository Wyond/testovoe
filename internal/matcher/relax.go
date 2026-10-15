package matcher

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
)

// relaxPCRE turns a PCRE pattern that Go cannot compile into a Go expression whose
// language contains the pattern's language under the PCRE2 options we run it with
// (UTF, DOLLAR_ENDONLY, no UCP). The prefilter analyses that expression, so its
// conditions stay necessary for the real pattern. Every step can only add matches:
//
//	lookahead / lookbehind (?=..) (?!..) (?<=..) (?<!..)  dropped
//	atomic group (?>..)                                   plain group
//	possessive X*+ X++ X?+ X{n}+                          greedy
//	backreference \1 \g{1} \k<name>                       (?s:.*)
//	\s \h \v \R \Z                                        PCRE's classes written out
//	repeat counts above 1000                              {min(n,1000),}
//
// Anything it does not understand (conditionals, recursion, \K, (?x) ...) gives "",
// and the rule is then an always-candidate.
func relaxPCRE(src, flags string) string {
	const (
		ws  = `\t\n\x0b\x0c\r `
		hws = `\t \x{a0}\x{1680}\x{180e}\x{2000}-\x{200a}\x{202f}\x{205f}\x{3000}`
		vws = `\n\x0b\x0c\r\x{85}\x{2028}\x{2029}`
	)
	var b strings.Builder
	depth, skip := 0, -1 // skip >= 0: inside a lookaround opened at that depth
	w := func(s string) {
		if skip < 0 {
			b.WriteString(s)
		}
	}
	n, quant := len(src), false
	for i := 0; i < n; {
		c := src[i]
		wasQuant := quant
		quant = false
		switch {
		case c == '\\' && i+1 < n:
			d := src[i+1]
			switch {
			case d >= '1' && d <= '9':
				j := i + 2
				for j < n && src[j] >= '0' && src[j] <= '9' {
					j++
				}
				w(`(?s:.*)`)
				i = j
				continue
			case d == 'g' || d == 'k':
				j := i + 2
				if j < n && (src[j] == '{' || src[j] == '<' || src[j] == '\'') {
					end := strings.IndexAny(src[j+1:], "}>'")
					if end < 0 {
						return ""
					}
					j += end + 2
				} else {
					for j < n && (src[j] >= '0' && src[j] <= '9' || src[j] == '-') {
						j++
					}
				}
				w(`(?s:.*)`)
				i = j
				continue
			case d == 'Q':
				end := strings.Index(src[i+2:], `\E`)
				if end < 0 {
					w(regexp.QuoteMeta(src[i+2:]))
					i = n
				} else {
					w(regexp.QuoteMeta(src[i+2 : i+2+end]))
					i += 2 + end + 2
				}
				continue
			case d == 's':
				w("[" + ws + "]")
			case d == 'S':
				w("[^" + ws + "]")
			case d == 'h':
				w("[" + hws + "]")
			case d == 'H':
				w("[^" + hws + "]")
			case d == 'v':
				w("[" + vws + "]")
			case d == 'V':
				w("[^" + vws + "]")
			case d == 'R':
				w(`(?:\r\n|[` + vws + `])`)
			case d == 'Z':
				w(`(?:\n?\z)`)
			case d == 'e':
				w(`\x1b`)
			case d == 'K' || d == 'G' || d == 'c' || d == 'X' || d == 'C' || d == 'N':
				return ""
			default:
				w(src[i : i+2])
			}
			i += 2
		case c == '[':
			j, cls, ok := relaxClass(src, i, ws, hws, vws)
			if !ok {
				return ""
			}
			w(cls)
			i = j
		case c == '(':
			rest := src[i+1:]
			switch {
			case strings.HasPrefix(rest, "?="), strings.HasPrefix(rest, "?!"),
				strings.HasPrefix(rest, "?<="), strings.HasPrefix(rest, "?<!"):
				if skip < 0 {
					w("(?:)")
					skip = depth
				}
				i += 3
				if strings.HasPrefix(rest, "?<") {
					i++
				}
			case strings.HasPrefix(rest, "?>"):
				w("(?:")
				i += 3
			case strings.HasPrefix(rest, "?#"):
				end := strings.IndexByte(rest, ')')
				if end < 0 {
					return ""
				}
				i += end + 2
				continue // a comment opens no group
			case strings.HasPrefix(rest, "?P<"), strings.HasPrefix(rest, "?<"), strings.HasPrefix(rest, "?'"):
				end := strings.IndexAny(rest[2:], ">'")
				if end < 0 {
					return ""
				}
				w("(")
				i += 1 + 2 + end + 1
			case strings.HasPrefix(rest, "?|"), strings.HasPrefix(rest, "?("), strings.HasPrefix(rest, "?R"),
				strings.HasPrefix(rest, "?&"), strings.HasPrefix(rest, "?P>"), strings.HasPrefix(rest, "?C"),
				len(rest) > 1 && rest[0] == '?' && (rest[1] >= '0' && rest[1] <= '9' || rest[1] == '+' || rest[1] == '-' && len(rest) > 2 && rest[2] >= '0' && rest[2] <= '9'):
				return "" // branch reset, conditionals, recursion, callouts
			default:
				w("(")
				i++
			}
			depth++
		case c == ')':
			depth--
			if skip == depth {
				skip = -1
			} else {
				w(")")
			}
			i++
		case c == '*' || c == '+' || c == '?':
			i++
			if wasQuant && c == '+' {
				continue // possessive -> greedy
			}
			w(string(c))
			quant = !wasQuant
		case c == '{':
			lo, hi, l, ok := parseRepeat(src[i:])
			if !ok {
				w(`\{`)
				i++
				continue
			}
			if lo > 1000 || hi > 1000 {
				w(fmt.Sprintf("{%d,}", min(lo, 1000)))
			} else {
				w(src[i : i+l])
			}
			quant = true
			i += l
		default:
			w(string(c))
			i++
		}
	}
	if skip >= 0 || depth != 0 {
		return ""
	}
	expr := b.String()
	if flags != "" {
		expr = "(?" + flags + ")" + expr
	}
	if _, err := syntax.Parse(expr, syntax.Perl); err != nil {
		return ""
	}
	return expr
}

// relaxClass copies a [...] class starting at src[i], writing PCRE's class escapes in a
// form Go reads the same way. It returns the index after the class.
func relaxClass(src string, i int, ws, hws, vws string) (int, string, bool) {
	var b strings.Builder
	b.WriteByte('[')
	i++
	if i < len(src) && src[i] == '^' {
		b.WriteByte('^')
		i++
	}
	if i < len(src) && src[i] == ']' {
		b.WriteString(`\]`)
		i++
	}
	for i < len(src) && src[i] != ']' {
		switch c := src[i]; {
		case c == '\\' && i+1 < len(src):
			switch d := src[i+1]; d {
			case 's':
				b.WriteString(ws)
			case 'h':
				b.WriteString(hws)
			case 'v':
				b.WriteString(vws)
			case 'b':
				b.WriteString(`\x08`)
			case 'e':
				b.WriteString(`\x1b`)
			case 'S', 'H', 'V', 'Q', 'E', 'c', 'N':
				return 0, "", false // negated or odd escapes inside a class
			default:
				b.WriteString(src[i : i+2])
			}
			i += 2
		case c == '[' && i+1 < len(src) && src[i+1] == ':':
			end := strings.Index(src[i:], ":]")
			if end < 0 {
				return 0, "", false
			}
			b.WriteString(src[i : i+end+2])
			i += end + 2
		case c == '[':
			b.WriteString(`\[`)
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	if i >= len(src) {
		return 0, "", false
	}
	b.WriteByte(']')
	return i + 1, b.String(), true
}

// parseRepeat recognises {n}, {n,} and {n,m} at the start of s; hi is -1 when unbounded.
func parseRepeat(s string) (lo, hi, length int, ok bool) {
	i := 1
	num := func() (int, bool) {
		st := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if st == i {
			return 0, false
		}
		v, err := strconv.Atoi(s[st:i])
		return v, err == nil
	}
	if lo, ok = num(); !ok || i >= len(s) {
		return 0, 0, 0, false
	}
	hi = lo
	if s[i] == ',' {
		i++
		if v, has := num(); has {
			hi = v
		} else {
			hi = -1
		}
	}
	if i >= len(s) || s[i] != '}' {
		return 0, 0, 0, false
	}
	return lo, hi, i + 1, true
}
