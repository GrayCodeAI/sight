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

func TestFormatContext_WithBlame(t *testing.T) {
	contexts := []FileContext{
		{
			Path:          "handler.go",
			RecentCommits: []string{"abc123 fix bug"},
			BlameSnippet:  "Alice(3), Bob(1)",
		},
	}
	out := FormatContext(contexts)
	if !strings.Contains(out, "handler.go") {
		t.Error("expected file path in output")
	}
	if !strings.Contains(out, "Alice(3), Bob(1)") {
		t.Error("expected blame snippet in output")
	}
	if !strings.Contains(out, "Blame:") {
		t.Error("expected Blame: label in output")
	}
}

func TestFormatContext_MultipleFiles(t *testing.T) {
	contexts := []FileContext{
		{
			Path:          "handler.go",
			RecentCommits: []string{"abc fix handler"},
		},
		{
			Path:          "util.go",
			RecentCommits: []string{"def refactor util"},
		},
	}
	out := FormatContext(contexts)
	if !strings.Contains(out, "handler.go") {
		t.Error("expected handler.go in output")
	}
	if !strings.Contains(out, "util.go") {
		t.Error("expected util.go in output")
	}
}

func TestFormatContext_MixedFilesWithAndWithoutCommits(t *testing.T) {
	contexts := []FileContext{
		{Path: "no-commits.go", RecentCommits: nil},
		{Path: "has-commits.go", RecentCommits: []string{"aaa commit msg"}},
		{Path: "also-empty.go", RecentCommits: []string{}},
	}
	out := FormatContext(contexts)
	if strings.Contains(out, "no-commits.go") {
		t.Error("files with no commits should be skipped")
	}
	if strings.Contains(out, "also-empty.go") {
		t.Error("files with empty commits should be skipped")
	}
	if !strings.Contains(out, "has-commits.go") {
		t.Error("files with commits should be included")
	}
}

func TestFormatContext_MultipleCommits(t *testing.T) {
	contexts := []FileContext{
		{
			Path: "main.go",
			RecentCommits: []string{
				"aaa first commit",
				"bbb second commit",
				"ccc third commit",
			},
		},
	}
	out := FormatContext(contexts)
	if !strings.Contains(out, "first commit") {
		t.Error("expected first commit")
	}
	if !strings.Contains(out, "second commit") {
		t.Error("expected second commit")
	}
	if !strings.Contains(out, "third commit") {
		t.Error("expected third commit")
	}
}

func TestParseBlameAuthors_SingleAuthor(t *testing.T) {
	input := "author Alice\nauthor Alice\nauthor Alice\n"
	result := parseBlameAuthors(input)
	if !strings.Contains(result, "Alice") {
		t.Error("expected Alice in result")
	}
	if !strings.Contains(result, "3") {
		t.Error("expected count 3 for Alice")
	}
}
