// Package diff parses unified diffs into structured representations.
package diff

import (
	"fmt"
	"strconv"
	"strings"
)

// File represents a single file's changes in a diff.
type File struct {
	Path    string
	OldPath string
	Hunks   []Hunk
	Added   bool
	Deleted bool
	Renamed bool
}

// Hunk represents a contiguous set of changes within a file.
type Hunk struct {
	OldStart int
	OldCount int
	NewStart int
	NewCount int
	Header   string
	Lines    []Line
}

// Line represents a single line in a hunk.
type Line struct {
	Type    LineType
	Content string
	OldNum  int
	NewNum  int
}

// LineType indicates whether a line was added, removed, or is context.
type LineType int

const (
	LineContext LineType = iota
	LineAdded
	LineRemoved
)

// Parse converts a unified diff string into structured File objects.
func Parse(raw string) []File {
	var files []File
	chunks := splitByFile(raw)

	for _, chunk := range chunks {
		file := parseFileChunk(chunk)
		if file.Path != "" {
			files = append(files, file)
		}
	}

	return files
}

// CombineFileChanges builds a unified diff string from FileChange inputs.
func CombineFileChanges(changes interface{}) string {
	type fc struct {
		Path    string
		OldPath string
		Diff    string
		Content string
	}

	var b strings.Builder
	// Accept []FileChange via interface to avoid circular import
	// The caller passes the correct type
	if arr, ok := changes.([]fc); ok {
		for _, c := range arr {
			if c.Diff != "" {
				b.WriteString(c.Diff)
				b.WriteString("\n")
			}
		}
	}
	return b.String()
}

func splitByFile(raw string) []string {
	lines := strings.Split(raw, "\n")
	var chunks []string
	var current []string

	for _, line := range lines {
		if strings.HasPrefix(line, "diff --git") {
			if len(current) > 0 {
				chunks = append(chunks, strings.Join(current, "\n"))
			}
			current = []string{line}
		} else {
			current = append(current, line)
		}
	}
	if len(current) > 0 {
		chunks = append(chunks, strings.Join(current, "\n"))
	}

	return chunks
}

func parseFileChunk(chunk string) File {
	lines := strings.Split(chunk, "\n")
	file := File{}

	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "--- a/"):
			file.OldPath = strings.TrimPrefix(line, "--- a/")
		case strings.HasPrefix(line, "--- /dev/null"):
			file.Added = true
		case strings.HasPrefix(line, "+++ b/"):
			file.Path = strings.TrimPrefix(line, "+++ b/")
		case strings.HasPrefix(line, "+++ /dev/null"):
			file.Deleted = true
		case strings.HasPrefix(line, "rename from "):
			file.OldPath = strings.TrimPrefix(line, "rename from ")
			file.Renamed = true
		case strings.HasPrefix(line, "rename to "):
			file.Path = strings.TrimPrefix(line, "rename to ")
		case strings.HasPrefix(line, "@@"):
			hunk := parseHunkHeader(line)
			hunk.Lines = parseHunkLines(lines[i+1:])
			file.Hunks = append(file.Hunks, hunk)
		}
	}

	if file.Path == "" && file.OldPath != "" {
		file.Path = file.OldPath
	}

	return file
}

func parseHunkHeader(line string) Hunk {
	hunk := Hunk{Header: line}

	// Parse @@ -old_start,old_count +new_start,new_count @@ header
	parts := strings.SplitN(line, "@@", 3)
	if len(parts) < 2 {
		return hunk
	}

	rangePart := strings.TrimSpace(parts[1])
	ranges := strings.Fields(rangePart)

	for _, r := range ranges {
		if strings.HasPrefix(r, "-") {
			start, count := parseRange(strings.TrimPrefix(r, "-"))
			hunk.OldStart = start
			hunk.OldCount = count
		} else if strings.HasPrefix(r, "+") {
			start, count := parseRange(strings.TrimPrefix(r, "+"))
			hunk.NewStart = start
			hunk.NewCount = count
		}
	}

	if len(parts) == 3 {
		hunk.Header = strings.TrimSpace(parts[2])
	}

	return hunk
}

func parseRange(s string) (int, int) {
	parts := strings.SplitN(s, ",", 2)
	start, _ := strconv.Atoi(parts[0])
	count := 1
	if len(parts) == 2 {
		count, _ = strconv.Atoi(parts[1])
	}
	return start, count
}

func parseHunkLines(lines []string) []Line {
	var result []Line
	oldNum := 0
	newNum := 0

	for _, line := range lines {
		if strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "diff --git") {
			break
		}

		switch {
		case strings.HasPrefix(line, "+"):
			newNum++
			result = append(result, Line{
				Type:    LineAdded,
				Content: strings.TrimPrefix(line, "+"),
				NewNum:  newNum,
			})
		case strings.HasPrefix(line, "-"):
			oldNum++
			result = append(result, Line{
				Type:    LineRemoved,
				Content: strings.TrimPrefix(line, "-"),
				OldNum:  oldNum,
			})
		case strings.HasPrefix(line, " "):
			oldNum++
			newNum++
			result = append(result, Line{
				Type:    LineContext,
				Content: strings.TrimPrefix(line, " "),
				OldNum:  oldNum,
				NewNum:  newNum,
			})
		default:
			if line == `\ No newline at end of file` {
				continue
			}
			oldNum++
			newNum++
			result = append(result, Line{
				Type:    LineContext,
				Content: line,
				OldNum:  oldNum,
				NewNum:  newNum,
			})
		}
	}

	return result
}

// Summary returns a human-readable summary of the diff.
func Summary(files []File) string {
	added, removed := 0, 0
	for _, f := range files {
		for _, h := range f.Hunks {
			for _, l := range h.Lines {
				switch l.Type {
				case LineAdded:
					added++
				case LineRemoved:
					removed++
				}
			}
		}
	}
	return fmt.Sprintf("%d files changed, %d insertions(+), %d deletions(-)", len(files), added, removed)
}
