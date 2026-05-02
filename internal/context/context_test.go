package context

import (
	"strings"
	"testing"
)

func TestFormatContext_Empty(t *testing.T) {
	out := FormatContext(nil)
	if out != "" {
		t.Error("expected empty string for nil input")
	}
}

func TestFormatContext_NoCommits(t *testing.T) {
	contexts := []FileContext{
		{Path: "main.go", RecentCommits: nil},
	}
	out := FormatContext(contexts)
	if strings.Contains(out, "main.go") {
		t.Error("should not include files with no commits")
	}
}

func TestFormatContext_WithCommits(t *testing.T) {
	contexts := []FileContext{
		{
			Path:          "handler.go",
			RecentCommits: []string{"abc123 fix auth bug", "def456 add rate limiting"},
		},
	}
	out := FormatContext(contexts)
	if !strings.Contains(out, "handler.go") {
		t.Error("expected file path in output")
	}
	if !strings.Contains(out, "fix auth bug") {
		t.Error("expected commit message in output")
	}
	if !strings.Contains(out, "Git Context") {
		t.Error("expected section header")
	}
}

func TestParseBlameAuthors(t *testing.T) {
	input := `abc1234 some line
author Alice
author-mail <alice@example.com>
author-time 1234567890
	code line here
def5678 another line
author Bob
author-mail <bob@example.com>
author-time 1234567891
	another code line
abc1234 third line
author Alice
author-mail <alice@example.com>
author-time 1234567892
	third code line
`
	result := parseBlameAuthors(input)
	if !strings.Contains(result, "Alice") {
		t.Error("expected Alice in blame output")
	}
	if !strings.Contains(result, "Bob") {
		t.Error("expected Bob in blame output")
	}
}

func TestParseBlameAuthors_Empty(t *testing.T) {
	result := parseBlameAuthors("")
	if result != "" {
		t.Error("expected empty string for empty input")
	}
}
