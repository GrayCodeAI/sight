package sight

import (
	"fmt"
	"regexp"
	"strings"
)

// TaintAnalyzer performs basic taint analysis / data flow tracking on Go code.
// It identifies taint sources (user-controlled inputs), tracks propagation through
// variable assignments and string concatenation, and reports when tainted data
// reaches a security-sensitive sink without sanitization.
//
// This is a function-level (not inter-procedural) analyzer operating on diff text.
type TaintAnalyzer struct{}

// TaintFinding represents a data-flow vulnerability where tainted data reaches a sink.
type TaintFinding struct {
	Source   string // description of the taint source
	Sink     string // description of the sink
	SinkType string // category: "sql_injection", "command_injection", "path_traversal", "log_leak"
	Variable string // the tainted variable name
	File     string
	Line     int
	Severity string
	CWE      string
	Message  string
	Fix      string
}

// NewTaintAnalyzer creates a TaintAnalyzer ready for use.
func NewTaintAnalyzer() *TaintAnalyzer {
	return &TaintAnalyzer{}
}

// AnalyzeDiff runs taint analysis on a unified diff, returning findings for Go files.
// Only added lines are analyzed. The analysis is function-scoped and tracks taint
// from source variables through assignments and string concatenation to sinks.
func (ta *TaintAnalyzer) AnalyzeDiff(rawDiff string) []Finding {
	// Parse diff into file blocks with added lines
	fileBlocks := parseDiffForTaint(rawDiff)
	var findings []Finding

	for _, fb := range fileBlocks {
		if !isGoFile(fb.path) {
			continue
		}
		taFindings := ta.analyzeFileBlock(fb.path, fb.lines)
		for _, tf := range taFindings {
			findings = append(findings, Finding{
				Concern:  "taint:data-flow",
				Severity: ParseSeverity(tf.Severity),
				File:     tf.File,
				Line:     tf.Line,
				Message:  fmt.Sprintf("[TAINT-%s] %s: %s → %s via variable %q", tf.SinkType, tf.SinkType, tf.Source, tf.Sink, tf.Variable),
				Fix:      tf.Fix,
				CWE:      tf.CWE,
			})
		}
	}
	return findings
}

// AnalyzeSource runs taint analysis on Go source code directly (not a diff).
// Useful for SAST integration with full file content.
func (ta *TaintAnalyzer) AnalyzeSource(source string, filePath string) []Finding {
	if !isGoFile(filePath) {
		return nil
	}
	lines := splitLines(source)
	fileLine := func(i int) diffLineInfo {
		return diffLineInfo{file: filePath, lineNum: i + 1, text: lines[i], added: true}
	}
	var dLines []diffLineInfo
	for i := range lines {
		dLines = append(dLines, fileLine(i))
	}
	taFindings := ta.analyzeFileBlock(filePath, dLines)
	var findings []Finding
	for _, tf := range taFindings {
		findings = append(findings, Finding{
			Concern:  "taint:data-flow",
			Severity: ParseSeverity(tf.Severity),
			File:     tf.File,
			Line:     tf.Line,
			Message:  fmt.Sprintf("[TAINT-%s] %s: %s → %s via variable %q", tf.SinkType, tf.SinkType, tf.Source, tf.Sink, tf.Variable),
			Fix:      tf.Fix,
			CWE:      tf.CWE,
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// Diff parsing
// ---------------------------------------------------------------------------

type diffBlock struct {
	path  string
	lines []diffLineInfo
}

type diffLineInfo struct {
	file    string
	lineNum int
	text    string
	added   bool
}

func parseDiffForTaint(rawDiff string) []diffBlock {
	var blocks []diffBlock
	var currentFile string
	var currentLines []diffLineInfo
	var lineNum int

	for _, raw := range strings.Split(rawDiff, "\n") {
		if strings.HasPrefix(raw, "+++ b/") {
			// Flush previous file
			if currentFile != "" && len(currentLines) > 0 {
				blocks = append(blocks, diffBlock{path: currentFile, lines: currentLines})
			}
			currentFile = strings.TrimPrefix(raw, "+++ b/")
			currentLines = nil
			lineNum = 0
			continue
		}
		if strings.HasPrefix(raw, "+++ ") {
			if currentFile != "" && len(currentLines) > 0 {
				blocks = append(blocks, diffBlock{path: currentFile, lines: currentLines})
			}
			currentFile = strings.TrimPrefix(raw, "+++ ")
			currentLines = nil
			lineNum = 0
			continue
		}
		if strings.HasPrefix(raw, "@@ ") {
			lineNum = parseHunkNewStart(raw) - 1
			continue
		}
		if strings.HasPrefix(raw, "+") && !strings.HasPrefix(raw, "+++") {
			lineNum++
			currentLines = append(currentLines, diffLineInfo{
				file:    currentFile,
				lineNum: lineNum,
				text:    raw[1:],
				added:   true,
			})
		} else if !strings.HasPrefix(raw, "-") {
			lineNum++
			// Include context lines for taint propagation tracking
			currentLines = append(currentLines, diffLineInfo{
				file:    currentFile,
				lineNum: lineNum,
				text:    raw,
				added:   false,
			})
		}
	}
	if currentFile != "" && len(currentLines) > 0 {
		blocks = append(blocks, diffBlock{path: currentFile, lines: currentLines})
	}
	return blocks
}

func isGoFile(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".go")
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// ---------------------------------------------------------------------------
// Source patterns — things that produce user-controlled data
// ---------------------------------------------------------------------------

type taintSource struct {
	Name    string
	Pattern *regexp.Regexp
}

var goTaintSources = []taintSource{
	// Function parameters — func declarations and method receivers
	{Name: "function-parameter", Pattern: regexp.MustCompile(`func\s+\(?\s*\w+\s+\*?\w+\)?\s+\w+\(([^)]*)\)`)},
	// os.Args access
	{Name: "os.Args", Pattern: regexp.MustCompile(`os\.Args\[`)},
	// os.Getenv
	{Name: "os.Getenv", Pattern: regexp.MustCompile(`os\.Getenv\s*\(`)},
	// ioutil.ReadAll / io.ReadAll from request body
	{Name: "request-body-read", Pattern: regexp.MustCompile(`(?:ioutil|io)\.ReadAll\s*\(\s*(?:r|req|request)\.Body`)},
	// r.FormValue / r.URL.Query().Get
	{Name: "http-form-value", Pattern: regexp.MustCompile(`(?:r|req|request)\.(?:FormValue|URL\.Query\(\)\.Get|PostFormValue|Header\.Get)\s*\(`)},
	// bufio.Scanner / fmt.Scan
	{Name: "stdin-read", Pattern: regexp.MustCompile(`(?:bufio\.NewScanner|fmt\.Scan|fmt\.Scanf|fmt\.Scanln|bufio\.NewReader\(os\.Stdin\))`)},
	// json.NewDecoder(r.Body).Decode
	{Name: "json-decode", Pattern: regexp.MustCompile(`json\.\w+Decoder.*\.Decode\s*\(`)},
	// flag.String / flag.Int etc
	{Name: "flag-arg", Pattern: regexp.MustCompile(`flag\.\w+\s*\(`)},
}

// ---------------------------------------------------------------------------
// Sink patterns — things that should not receive tainted data
// ---------------------------------------------------------------------------

type taintSink struct {
	Name    string
	CWE     string
	Fix     string
	Pattern *regexp.Regexp
}

var goTaintSinks = []taintSink{
	// SQL injection — match any .Query(), .QueryRow(), .Exec() call
	{
		Name:    "SQL query execution",
		CWE:     "CWE-89",
		Fix:     "Use parameterized queries with db.Query(sql, args...) instead of string concatenation",
		Pattern: regexp.MustCompile(`(?:\.Query|\.QueryRow|\.Exec)\s*\(`),
	},
	// Command injection
	{
		Name:    "command execution",
		CWE:     "CWE-78",
		Fix:     "Validate and sanitize input before passing to exec.Command; use an allowlist of commands",
		Pattern: regexp.MustCompile(`exec\.Command\s*\(`),
	},
	// Path traversal — os.Open, os.Create, os.ReadFile, os.WriteFile
	{
		Name:    "file operation",
		CWE:     "CWE-22",
		Fix:     "Use filepath.Clean() and validate the path is within the expected directory",
		Pattern: regexp.MustCompile(`os\.(?:Open|Create|ReadFile|WriteFile|Remove|MkdirAll)\s*\(`),
	},
	// HTTP response writing with tainted data
	{
		Name:    "HTTP response write",
		CWE:     "CWE-79",
		Fix:     "Sanitize output before writing to HTTP response to prevent XSS",
		Pattern: regexp.MustCompile(`(?:w|rw|resp|response)\.(?:Write|WriteHeader)\s*\(`),
	},
	// Log output
	{
		Name:    "log output",
		CWE:     "CWE-532",
		Fix:     "Avoid logging sensitive user data; redact or mask before logging",
		Pattern: regexp.MustCompile(`(?:log\.|slog\.|logger\.|fmt\.Print)(?:Println|Printf|Info|Debug|Warn|Error|Fatal|Sprintf|Sprintln)`),
	},
	// Template execution (XSS)
	{
		Name:    "template execution",
		CWE:     "CWE-79",
		Fix:     "Use html/template instead of text/template; sanitize user input before template rendering",
		Pattern: regexp.MustCompile(`\.Execute\s*\(`),
	},
}

// ---------------------------------------------------------------------------
// Sanitizer patterns — operations that clean tainted data
// ---------------------------------------------------------------------------

var goSanitizers = []string{
	`filepath\.Clean`,
	`url\.QueryEscape`,
	`html\.EscapeString`,
	`strconv\.Quote`,
	`regexp\.\w+\.ReplaceAll`,
	`strings\.Replace`,
	`template\.HTML`,
	`\.\s*Whitelist`,
	`\.\s*Sanitize`,
	`validate`,
	`int\s*\(`, // type conversion to int sanitizes string input
}

// ---------------------------------------------------------------------------
// Core analysis engine
// ---------------------------------------------------------------------------

// funcParamPattern matches Go function signatures to extract parameter names.
var funcParamPattern = regexp.MustCompile(`func\s+(?:\(\s*\w+\s+\*?\w+\s*\)\s+)?(\w+)\s*\(([^)]*)\)`)

// assignPattern matches variable assignments: x := expr, x = expr, var x = expr
var assignPattern = regexp.MustCompile(`^\s*(?:(?:var|const)\s+)?(\w+)\s*(?::=|=\s*)(.+)$`)

// shortAssignPattern matches short declarations: x := something
var shortAssignPattern = regexp.MustCompile(`^\s*(\w+)\s*:=\s*(.+)$`)

// concatPattern detects string concatenation with +
var concatOp = "+"

func (ta *TaintAnalyzer) analyzeFileBlock(filePath string, lines []diffLineInfo) []TaintFinding {
	var findings []TaintFinding

	// taintedVars maps variable names to their taint source description.
	// We reset taint state at function boundaries for function-level analysis.
	taintedVars := make(map[string]string)

	for _, dl := range lines {
		text := strings.TrimSpace(dl.text)

		// Detect function boundaries — reset taint tracking
		if funcParamPattern.MatchString(text) {
			taintedVars = make(map[string]string)
			// Extract parameters and mark them as tainted
			params := extractFuncParams(text)
			for _, p := range params {
				taintedVars[p] = "function-parameter"
			}
			// Also check sources in the function signature itself
			for _, src := range goTaintSources {
				if src.Pattern.MatchString(text) && src.Name != "function-parameter" {
					for _, p := range params {
						taintedVars[p] = src.Name
					}
				}
			}
			continue
		}

		// Track taint propagation through variable assignments
		ta.trackAssignment(text, taintedVars)

		// Check if any tainted variable flows into a sink
		for varName, source := range taintedVars {
			if !dl.added {
				continue
			}
			if strings.Contains(text, varName) {
				// Check if it's sanitized before reaching the sink
				if isSanitized(text) {
					continue
				}
				// Check each sink
				for _, sink := range goTaintSinks {
					if sink.Pattern.MatchString(text) {
						// Make sure the tainted variable is actually in the sink call
						if ta.varInSinkCall(text, varName, sink.Name) {
							findings = append(findings, TaintFinding{
								Source:   source,
								Sink:     sink.Name,
								SinkType: sinkToType(sink.Name),
								Variable: varName,
								File:     filePath,
								Line:     dl.lineNum,
								Severity: sinkSeverity(sink.CWE),
								CWE:      sink.CWE,
								Message:  fmt.Sprintf("Tainted data from %s flows to %s without sanitization", source, sink.Name),
								Fix:      sink.Fix,
							})
						}
					}
				}
			}
		}
	}

	return findings
}

// trackAssignment updates taintedVars based on variable assignments in the line.
func (ta *TaintAnalyzer) trackAssignment(text string, taintedVars map[string]string) {
	// Check short assignment: x := expr
	if m := shortAssignPattern.FindStringSubmatch(text); len(m) == 3 {
		varName := m[1]
		expr := m[2]

		// If the RHS applies a sanitizer, the result is clean — don't propagate taint
		if isSanitized(expr) {
			delete(taintedVars, varName)
			return
		}

		// Check if RHS contains a direct taint source
		for _, src := range goTaintSources {
			if src.Pattern.MatchString(expr) {
				taintedVars[varName] = src.Name
				return
			}
		}

		// Check if RHS references any tainted variable
		for taintedVar, source := range taintedVars {
			if strings.Contains(expr, taintedVar) {
				taintedVars[varName] = source
				return
			}
		}

		// If RHS is just a literal, constant, or clean, ensure varName is NOT tainted
		delete(taintedVars, varName)
		return
	}

	// Check var declaration: var x = expr
	if m := assignPattern.FindStringSubmatch(text); len(m) == 3 {
		varName := m[1]
		expr := m[2]

		if isSanitized(expr) {
			delete(taintedVars, varName)
			return
		}

		for _, src := range goTaintSources {
			if src.Pattern.MatchString(expr) {
				taintedVars[varName] = src.Name
				return
			}
		}
		for taintedVar, source := range taintedVars {
			if strings.Contains(expr, taintedVar) {
				taintedVars[varName] = source
				return
			}
		}
		delete(taintedVars, varName)
	}
}

// varInSinkCall checks if a variable name appears in the arguments of a sink call.
func (ta *TaintAnalyzer) varInSinkCall(text string, varName string, sinkName string) bool {
	// For SQL sinks, check if tainted var is in the query argument
	if strings.Contains(text, "Query") || strings.Contains(text, "Exec") {
		return strings.Contains(text, varName)
	}
	// For exec.Command, check if tainted var is an argument
	if strings.Contains(text, "exec.Command") {
		return strings.Contains(text, varName)
	}
	// For file ops, check if tainted var is in the path
	if strings.Contains(text, "os.") {
		return strings.Contains(text, varName)
	}
	// For HTTP response, log, template — check general presence
	return strings.Contains(text, varName)
}

// isSanitized checks if a line contains sanitization patterns.
func isSanitized(text string) bool {
	for _, pattern := range goSanitizers {
		if matched, _ := regexp.MatchString(pattern, text); matched {
			return true
		}
	}
	return false
}

// extractFuncParams extracts parameter names from a Go function signature.
func extractFuncParams(sig string) []string {
	m := funcParamPattern.FindStringSubmatch(sig)
	if len(m) < 3 {
		return nil
	}
	paramStr := m[2]
	var params []string
	for _, part := range strings.Split(paramStr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Handle: name type, name1, name2 type, _ type
		tokens := strings.Fields(part)
		if len(tokens) >= 1 {
			name := tokens[0]
			// Skip type-only params (e.g., in func(int, string))
			if !isBuiltinType(name) && name != "error" && name != "any" {
				params = append(params, name)
			}
		}
	}
	return params
}

func isBuiltinType(s string) bool {
	switch s {
	case "int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64",
		"float32", "float64", "complex64", "complex128",
		"bool", "string", "byte", "rune", "uintptr",
		"error", "any", "interface{}":
		return true
	}
	return false
}

func sinkToType(name string) string {
	switch {
	case strings.Contains(name, "SQL"):
		return "SQL_INJECTION"
	case strings.Contains(name, "command"):
		return "COMMAND_INJECTION"
	case strings.Contains(name, "file"):
		return "PATH_TRAVERSAL"
	case strings.Contains(name, "HTTP") || strings.Contains(name, "response"):
		return "XSS"
	case strings.Contains(name, "log"):
		return "LOG_LEAK"
	case strings.Contains(name, "template"):
		return "XSS"
	default:
		return "TAINT_FLOW"
	}
}

func sinkSeverity(cwe string) string {
	switch cwe {
	case "CWE-89": // SQL injection
		return "critical"
	case "CWE-78": // Command injection
		return "critical"
	case "CWE-22": // Path traversal
		return "high"
	case "CWE-79": // XSS
		return "high"
	case "CWE-532": // Log leak
		return "medium"
	default:
		return "medium"
	}
}
