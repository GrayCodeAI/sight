// Package context provides git and code context enrichment for diffs.
package context

import (
	"os/exec"
	"strings"
)

// BlameInfo contains git blame information for a file region.
type BlameInfo struct {
	File    string
	Lines   []BlameLine
}

// BlameLine is a single line's blame data.
type BlameLine struct {
	Hash    string
	Author  string
	Date    string
	Line    int
	Content string
}

// Blame runs git blame on the specified file and line range.
func Blame(file string, startLine, endLine int) (*BlameInfo, error) {
	args := []string{"blame", "--porcelain"}
	if startLine > 0 && endLine > 0 {
		args = append(args, "-L", strings.Join([]string{itoa(startLine), itoa(endLine)}, ","))
	}
	args = append(args, "--", file)

	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return nil, err
	}

	return parseBlame(file, string(out)), nil
}

// RecentCommits returns the last N commits that touched a file.
func RecentCommits(file string, n int) ([]string, error) {
	out, err := exec.Command("git", "log", "--oneline", "-n", itoa(n), "--", file).Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	return lines, nil
}

// DiffBase returns the diff of the current branch against a base branch.
func DiffBase(base string) (string, error) {
	out, err := exec.Command("git", "diff", base+"...HEAD").Output()
	if err != nil {
		out2, err2 := exec.Command("git", "diff", base).Output()
		if err2 != nil {
			return "", err
		}
		return string(out2), nil
	}
	return string(out), nil
}

// ChangedFiles returns the list of files changed relative to a base.
func ChangedFiles(base string) ([]string, error) {
	out, err := exec.Command("git", "diff", "--name-only", base+"...HEAD").Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	return lines, nil
}

func parseBlame(file, output string) *BlameInfo {
	info := &BlameInfo{File: file}
	lines := strings.Split(output, "\n")
	lineNum := 0

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		parts := strings.Fields(line)
		if len(parts) >= 3 && len(parts[0]) == 40 {
			lineNum++
			bl := BlameLine{
				Hash: parts[0],
				Line: lineNum,
			}
			for i++; i < len(lines); i++ {
				inner := lines[i]
				if strings.HasPrefix(inner, "author ") {
					bl.Author = strings.TrimPrefix(inner, "author ")
				} else if strings.HasPrefix(inner, "author-time ") {
					bl.Date = strings.TrimPrefix(inner, "author-time ")
				} else if strings.HasPrefix(inner, "\t") {
					bl.Content = strings.TrimPrefix(inner, "\t")
					break
				}
			}
			info.Lines = append(info.Lines, bl)
		}
	}

	return info
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
