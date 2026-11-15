package provider

import (
	"strings"
	"testing"
)

func TestCanonicalTXT(t *testing.T) {
	cases := map[string]string{
		`heritage=external-dns`:          `"heritage=external-dns"`,
		`"heritage=external-dns"`:        `"heritage=external-dns"`,
		`"abc" "def"`:                    `"abcdef"`,
		`say "hi"`:                       `"say \"hi\""`,
		`"say \"hi\""`:                   `"say \"hi\""`,
		`"caf\195\169"`:                  `"caf\195\169"`,
		"café":                           `"caf\195\169"`,
		`"unterminated`:                  `"\"unterminated"`,
		`"a" junk`:                       `"\"a\" junk"`,
		`v=spf1 include:_spf.x.com ~all`: `"v=spf1 include:_spf.x.com ~all"`,
	}
	for in, want := range cases {
		if got := canonicalTXT(in); got != want {
			t.Errorf("canonicalTXT(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestSplitTXT(t *testing.T) {
	content := strings.Repeat("a", 300)
	got := splitTXT(`"` + content + `"`)
	want := `"` + strings.Repeat("a", 255) + `" "` + strings.Repeat("a", 45) + `"`
	if got != want {
		t.Fatalf("splitTXT = %s", got)
	}
	if back := canonicalTXT(got); back != `"`+content+`"` {
		t.Fatalf("round trip = %s", back)
	}
}
