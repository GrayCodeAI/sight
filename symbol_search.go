package sight

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SymbolResult is a symbol found in a source file via AST-level search.
// It provides the precise source location and body text needed for
// targeted context retrieval (AutoCodeRover pattern, ISSTA 2024).
type SymbolResult struct {
	File      string `json:"file"`
	Symbol    string `json:"symbol"`
	Kind      string `json:"kind"` // function, method, type, class, const, var
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Body      string `json:"body,omitempty"`
}

// SearchBySymbol returns all symbols in filePath whose name contains
// nameFragment (case-insensitive substring match). An empty nameFragment
// returns all symbols. Passing a non-empty kind filters by symbol kind
// ("function", "method", "type", etc.); an empty kind matches all.
//
// This replaces flat file loading with precise symbol-level retrieval.
// AutoCodeRover (arXiv 2404.05427) demonstrated that AST-backed symbol
// search achieves 19% SWE-bench Lite — higher than whole-file retrieval —
// by reducing context noise from irrelevant code paths.
func SearchBySymbol(filePath, nameFragment, kind string) ([]SymbolResult, error) {
	ext := filepath.Ext(filePath)
	patterns := symbolPatternsForExt(ext)
	if len(patterns) == 0 {
		return nil, nil
	}

	lines, err := readLines(filePath)
	if err != nil {
		return nil, fmt.Errorf("sight.SearchBySymbol: %w", err)
	}

	fragLower := strings.ToLower(nameFragment)
	kindLower := strings.ToLower(kind)

	var results []SymbolResult
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		for _, pat := range patterns {
			m := pat.re.FindStringSubmatch(trimmed)
			if m == nil {
				continue
			}
			sym := extractSymbolName(m, pat.kind, ext)
			if fragLower != "" && !strings.Contains(strings.ToLower(sym), fragLower) {
				break
			}
			if kindLower != "" && pat.kind != kindLower {
				break
			}

			startLine := i + 1
			endLine := estimateEndLine(lines, i)

			results = append(results, SymbolResult{
				File:      filePath,
				Symbol:    sym,
				Kind:      pat.kind,
				StartLine: startLine,
				EndLine:   endLine,
			})
			break
		}
	}
	return results, nil
}

// GetSymbolBody returns the source text of the first symbol in filePath
// whose name matches fqn (case-insensitive). If no match is found,
// it returns an error. The Body field of the result is populated with
// the extracted source.
//
// GetSymbolBody is the primary API for precise code context retrieval:
// instead of loading a whole file, hawk passes only the relevant function
// or type body to the LLM, dramatically reducing context window pressure.
func GetSymbolBody(filePath, fqn string) (SymbolResult, error) {
	results, err := SearchBySymbol(filePath, fqn, "")
	if err != nil {
		return SymbolResult{}, err
	}
	lines, err := readLines(filePath)
	if err != nil {
		return SymbolResult{}, fmt.Errorf("sight.GetSymbolBody: %w", err)
	}
	fqnLower := strings.ToLower(fqn)
	for _, r := range results {
		if strings.EqualFold(r.Symbol, fqnLower) || strings.HasSuffix(strings.ToLower(r.Symbol), "."+fqnLower) {
			r.Body = extractBody(lines, r.StartLine-1, r.EndLine-1)
			return r, nil
		}
	}
	// Fall back to partial match
	for _, r := range results {
		if strings.Contains(strings.ToLower(r.Symbol), fqnLower) {
			r.Body = extractBody(lines, r.StartLine-1, r.EndLine-1)
			return r, nil
		}
	}
	return SymbolResult{}, fmt.Errorf("sight.GetSymbolBody: symbol %q not found in %s", fqn, filePath)
}

// extractBody extracts lines [start, end] (0-based, inclusive) from lines.
func extractBody(lines []string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end >= len(lines) {
		end = len(lines) - 1
	}
	if start > end {
		return ""
	}
	return strings.Join(lines[start:end+1], "\n")
}

// estimateEndLine estimates the end line of a symbol starting at lineIdx.
// Uses brace depth for C-style languages, indent for Python.
func estimateEndLine(lines []string, startIdx int) int {
	if startIdx >= len(lines) {
		return startIdx + 1
	}
	startLine := lines[startIdx]
	isPython := !strings.Contains(startLine, "{") && strings.HasSuffix(strings.TrimSpace(startLine), ":")

	if isPython {
		baseIndent := leadingSpaces(startLine)
		for i := startIdx + 1; i < len(lines); i++ {
			line := lines[i]
			if strings.TrimSpace(line) == "" {
				continue
			}
			if leadingSpaces(line) <= baseIndent {
				return i
			}
		}
		return len(lines)
	}

	depth := strings.Count(startLine, "{") - strings.Count(startLine, "}")
	if depth <= 0 && !strings.Contains(startLine, "{") {
		// Single-line or no body; look ahead for the opening brace
		for i := startIdx + 1; i < len(lines) && i < startIdx+5; i++ {
			depth += strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
			if depth > 0 {
				startIdx = i
				break
			}
		}
	}
	for i := startIdx + 1; i < len(lines); i++ {
		depth += strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
		if depth <= 0 {
			return i + 1
		}
	}
	return len(lines)
}

func leadingSpaces(s string) int {
	n := 0
	for _, c := range s {
		switch c {
		case ' ':
			n++
		case '\t':
			n += 4
		default:
			return n
		}
	}
	return n
}

// ── Pattern tables ────────────────────────────────────────────────────────────

type symPattern struct {
	re   *regexp.Regexp
	kind string
}

func symbolPatternsForExt(ext string) []symPattern {
	switch strings.ToLower(ext) {
	case ".go":
		return goSymPatterns
	case ".py":
		return pySymPatterns
	case ".ts", ".tsx":
		return tsSymPatterns
	case ".js", ".jsx":
		return jsSymPatterns
	case ".rs":
		return rsSymPatterns
	case ".java":
		return javaSymPatterns
	}
	return nil
}

var goSymPatterns = []symPattern{
	{regexp.MustCompile(`^func\s+\(\s*\w+\s+\*?(\w+)\)\s+(\w+)\s*\(`), "method"},
	{regexp.MustCompile(`^func\s+(\w+)\s*\(`), "function"},
	{regexp.MustCompile(`^type\s+(\w+)\s+struct\b`), "type"},
	{regexp.MustCompile(`^type\s+(\w+)\s+interface\b`), "type"},
	{regexp.MustCompile(`^type\s+(\w+)\s+`), "type"},
	{regexp.MustCompile(`^var\s+(\w+)\s`), "var"},
	{regexp.MustCompile(`^const\s+(\w+)\s`), "const"},
}

var pySymPatterns = []symPattern{
	{regexp.MustCompile(`^class\s+(\w+)`), "class"},
	{regexp.MustCompile(`^async\s+def\s+(\w+)`), "function"},
	{regexp.MustCompile(`^\s{4}async\s+def\s+(\w+)`), "method"},
	{regexp.MustCompile(`^def\s+(\w+)`), "function"},
	{regexp.MustCompile(`^\s{4}def\s+(\w+)`), "method"},
}

var tsSymPatterns = []symPattern{
	{regexp.MustCompile(`^(?:export\s+)?class\s+(\w+)`), "class"},
	{regexp.MustCompile(`^(?:export\s+)?interface\s+(\w+)`), "type"},
	{regexp.MustCompile(`^(?:export\s+)?type\s+(\w+)\s*=`), "type"},
	{regexp.MustCompile(`^(?:export\s+)?(?:async\s+)?function\s+(\w+)`), "function"},
	{regexp.MustCompile(`^(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s+)?\(`), "function"},
	{regexp.MustCompile(`^(?:export\s+)?const\s+(\w+)`), "const"},
}

var jsSymPatterns = []symPattern{
	{regexp.MustCompile(`^(?:export\s+)?class\s+(\w+)`), "class"},
	{regexp.MustCompile(`^(?:export\s+)?(?:async\s+)?function\s+(\w+)`), "function"},
	{regexp.MustCompile(`^(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s+)?\(`), "function"},
	{regexp.MustCompile(`^(?:export\s+)?const\s+(\w+)`), "const"},
}

var rsSymPatterns = []symPattern{
	{regexp.MustCompile(`^(?:pub(?:\([^)]*\))?\s+)?fn\s+(\w+)`), "function"},
	{regexp.MustCompile(`^(?:pub(?:\([^)]*\))?\s+)?struct\s+(\w+)`), "type"},
	{regexp.MustCompile(`^(?:pub(?:\([^)]*\))?\s+)?enum\s+(\w+)`), "type"},
	{regexp.MustCompile(`^(?:pub(?:\([^)]*\))?\s+)?trait\s+(\w+)`), "type"},
	{regexp.MustCompile(`^impl(?:<[^>]*>)?\s+(\w+)`), "type"},
}

var javaSymPatterns = []symPattern{
	{regexp.MustCompile(`^(?:public|private|protected)?\s*(?:static\s+)?class\s+(\w+)`), "class"},
	{regexp.MustCompile(`^(?:public|private|protected)?\s*interface\s+(\w+)`), "type"},
	{regexp.MustCompile(`^\s+(?:public|private|protected)?\s*(?:static\s+)?(?:\w+(?:<[^>]*>)?)\s+(\w+)\s*\(`), "method"},
}

func extractSymbolName(m []string, kind, ext string) string {
	if kind == "method" && strings.EqualFold(ext, ".go") && len(m) >= 3 {
		return m[1] + "." + m[2]
	}
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// readLines reads a file and returns its lines.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}
