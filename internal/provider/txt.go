package provider

import (
	"strconv"
	"strings"
)

// maxTXTString is the length limit of one character-string in a TXT record
// (RFC 1035 §3.3). Longer content has to travel as several strings.
const maxTXTString = 255

// The webhook has ONE form for a TXT value, and every path goes through it:
// the whole content, unsplit, inside a single pair of double quotes, with
// `"`, `\` and non-printable bytes escaped the way the DNS presentation
// format escapes them.
//
// It matters because external-dns compares what it wants (after
// adjustendpoints) with what /records returns, as strings. The primary hands
// back long values split into 255-byte strings ("aaa…" "bbb…") and short ones
// quoted; external-dns produces its ownership record either with or without
// quotes depending on the version. Unless both sides land on the same string,
// every cycle looks like a change and the record is rewritten forever.

// canonicalTXT turns any TXT value, as external-dns or the primary wrote it,
// into the canonical form.
func canonicalTXT(value string) string {
	return quoteTXT(txtContent(value))
}

// txtContent returns the raw bytes a TXT value stands for.
//
// A value that starts with a double quote is read as presentation format: one
// or more quoted strings, concatenated. Anything else is taken literally,
// which is how external-dns and most users write a TXT target.
func txtContent(value string) string {
	v := strings.TrimSpace(value)
	if !strings.HasPrefix(v, `"`) {
		return value
	}
	content, ok := parsePresentation(v)
	if !ok {
		return value
	}
	return content
}

// parsePresentation decodes a sequence of quoted character-strings. ok is
// false when the input is not well formed, in which case the caller keeps
// the value as it came.
func parsePresentation(s string) (string, bool) {
	var out strings.Builder
	i := 0
	for i < len(s) {
		switch s[i] {
		case ' ', '\t':
			i++
			continue
		case '"':
		default:
			return "", false
		}
		i++ // opening quote
		closed := false
		for i < len(s) {
			c := s[i]
			if c == '"' {
				closed = true
				i++
				break
			}
			if c != '\\' {
				out.WriteByte(c)
				i++
				continue
			}
			// Escape: \DDD is a decimal byte, \X is X.
			if i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
				n, _ := strconv.Atoi(s[i+1 : i+4])
				if n > 255 {
					return "", false
				}
				out.WriteByte(byte(n))
				i += 4
				continue
			}
			if i+1 >= len(s) {
				return "", false
			}
			out.WriteByte(s[i+1])
			i += 2
		}
		if !closed {
			return "", false
		}
	}
	return out.String(), true
}

// quoteTXT is the canonical single quoted string.
func quoteTXT(content string) string {
	return `"` + escapeTXT(content) + `"`
}

// splitTXT is the form sent to dns-api: the content cut into strings of at
// most 255 bytes, each quoted. The cut is on raw bytes, before escaping, so
// an escape sequence is never split across two strings.
func splitTXT(value string) string {
	content := txtContent(value)
	if content == "" {
		return `""`
	}
	parts := make([]string, 0, len(content)/maxTXTString+1)
	for len(content) > 0 {
		n := min(len(content), maxTXTString)
		parts = append(parts, quoteTXT(content[:n]))
		content = content[n:]
	}
	return strings.Join(parts, " ")
}

func escapeTXT(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7e:
			b.WriteByte('\\')
			b.WriteString(strconv.Itoa(int(c) + 1000)[1:]) // zero-padded to three digits
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
