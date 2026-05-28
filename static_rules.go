package sight

import (
	"fmt"
	"regexp"
	"strings"
)

// StaticRule defines a pattern-based static analysis rule that can catch common
// issues without invoking an LLM. Rules are matched against diff content or full
// file content before the LLM review pass, saving tokens on obvious issues.
type StaticRule struct {
	ID          string         // unique identifier, e.g. "SEC-GO-001"
	Name        string         // short human-readable name
	Description string         // detailed explanation
	Language    string         // "go", "python", "typescript", "javascript", "any"
	Pattern     *regexp.Regexp // primary detection pattern
	Antipattern *regexp.Regexp // if this also matches the same line, suppress the finding
	Severity    string         // "critical", "high", "medium", "low"
	Category    string         // "security", "correctness", "performance"
	CWE         string         // e.g., "CWE-89"
	Fix         string         // suggested fix description
}

// StaticAnalyzer runs pattern-based rules against code before the LLM review.
type StaticAnalyzer struct {
	Rules []StaticRule
}

// NewStaticAnalyzer creates a StaticAnalyzer preloaded with the default rule set.
func NewStaticAnalyzer() *StaticAnalyzer {
	return &StaticAnalyzer{
		Rules: defaultRules(),
	}
}

// Analyze runs all matching rules against a unified diff string and returns findings.
// Only added lines (starting with "+") are checked. The language parameter filters
// rules to those matching the language or "any".
func (sa *StaticAnalyzer) Analyze(diff string, language string) []Finding {
	var findings []Finding

	// Parse diff to extract added lines with file and line info
	type diffLine struct {
		file    string
		lineNum int
		text    string
	}

	var lines []diffLine
	var currentFile string
	var lineNum int

	for _, raw := range strings.Split(diff, "\n") {
		if strings.HasPrefix(raw, "+++ b/") {
			currentFile = strings.TrimPrefix(raw, "+++ b/")
			lineNum = 0
			continue
		}
		if strings.HasPrefix(raw, "+++ ") {
			currentFile = strings.TrimPrefix(raw, "+++ ")
			lineNum = 0
			continue
		}
		if strings.HasPrefix(raw, "@@ ") {
			// Parse hunk header for line number: @@ -a,b +c,d @@
			lineNum = parseHunkNewStart(raw) - 1
			continue
		}
		if strings.HasPrefix(raw, "+") && !strings.HasPrefix(raw, "+++") {
			lineNum++
			lines = append(lines, diffLine{
				file:    currentFile,
				lineNum: lineNum,
				text:    raw[1:], // strip leading "+"
			})
		} else if !strings.HasPrefix(raw, "-") {
			lineNum++
		}
	}

	lang := strings.ToLower(language)
	for _, rule := range sa.Rules {
		if rule.Language != "any" && rule.Language != lang {
			continue
		}
		for _, dl := range lines {
			if rule.Pattern.MatchString(dl.text) {
				// Check antipattern — if it matches, this is a false positive
				if rule.Antipattern != nil && rule.Antipattern.MatchString(dl.text) {
					continue
				}
				findings = append(findings, Finding{
					Concern:  "static:" + rule.Category,
					Severity: ParseSeverity(rule.Severity),
					File:     dl.file,
					Line:     dl.lineNum,
					Message:  fmt.Sprintf("[%s] %s: %s", rule.ID, rule.Name, rule.Description),
					Fix:      rule.Fix,
					CWE:      rule.CWE,
				})
			}
		}
	}

	return findings
}

// AnalyzeFile runs all matching rules against a full file's content.
// Each line is checked independently. The language parameter filters rules.
func (sa *StaticAnalyzer) AnalyzeFile(content string, language string) []Finding {
	var findings []Finding
	lang := strings.ToLower(language)

	lines := strings.Split(content, "\n")
	for _, rule := range sa.Rules {
		if rule.Language != "any" && rule.Language != lang {
			continue
		}
		for i, line := range lines {
			if rule.Pattern.MatchString(line) {
				if rule.Antipattern != nil && rule.Antipattern.MatchString(line) {
					continue
				}
				findings = append(findings, Finding{
					Concern:  "static:" + rule.Category,
					Severity: ParseSeverity(rule.Severity),
					File:     "",
					Line:     i + 1,
					Message:  fmt.Sprintf("[%s] %s: %s", rule.ID, rule.Name, rule.Description),
					Fix:      rule.Fix,
					CWE:      rule.CWE,
				})
			}
		}
	}

	return findings
}

// AnalyzeFileWithPath is like AnalyzeFile but sets the File field on findings.
func (sa *StaticAnalyzer) AnalyzeFileWithPath(content string, language string, path string) []Finding {
	findings := sa.AnalyzeFile(content, language)
	for i := range findings {
		findings[i].File = path
	}
	return findings
}

// DetectLanguage guesses the language from a file path extension.
func DetectLanguage(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".go"):
		return "go"
	case strings.HasSuffix(lower, ".py"):
		return "python"
	case strings.HasSuffix(lower, ".ts"):
		return "typescript"
	case strings.HasSuffix(lower, ".tsx"):
		return "typescript"
	case strings.HasSuffix(lower, ".js"):
		return "javascript"
	case strings.HasSuffix(lower, ".jsx"):
		return "javascript"
	default:
		return "any"
	}
}

// parseHunkNewStart extracts the new-file start line from a hunk header.
// Format: @@ -old,count +new,count @@
func parseHunkNewStart(header string) int {
	// Find "+N" after the first space
	idx := strings.Index(header, "+")
	if idx < 0 {
		return 1
	}
	rest := header[idx+1:]
	var n int
	for _, ch := range rest {
		if ch >= '0' && ch <= '9' {
			n = n*10 + int(ch-'0')
		} else {
			break
		}
	}
	if n == 0 {
		return 1
	}
	return n
}

// defaultRules returns the built-in set of 30+ static analysis rules.
func defaultRules() []StaticRule {
	return []StaticRule{
		// =====================================================================
		// SECURITY - Go
		// =====================================================================
		{
			ID:          "SEC-GO-001",
			Name:        "SQL Injection",
			Description: "String formatting used in SQL query construction; use parameterized queries instead",
			Language:    "go",
			Pattern:     regexp.MustCompile(`fmt\.Sprintf\s*\(\s*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"]*%[sv]`),
			Antipattern: nil,
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-89",
			Fix:         "Use parameterized queries with ? or $1 placeholders instead of fmt.Sprintf for SQL",
		},
		{
			ID:          "SEC-GO-002",
			Name:        "Command Injection",
			Description: "Potentially unsanitized input passed to exec.Command",
			Language:    "go",
			Pattern:     regexp.MustCompile(`exec\.Command\s*\([^"` + "`" + `][^,)]*\)`),
			Antipattern: regexp.MustCompile(`exec\.Command\s*\(\s*"[^"]+"\s*\)`),
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-78",
			Fix:         "Validate and sanitize all input passed to exec.Command; use an allowlist of permitted commands",
		},
		{
			ID:          "SEC-GO-003",
			Name:        "Path Traversal",
			Description: "User-controlled path used in file operations without filepath.Clean or validation",
			Language:    "go",
			Pattern:     regexp.MustCompile(`(?:os\.(?:Open|ReadFile|Create|WriteFile)|filepath\.Join)\s*\(.*(?:req\.|r\.|input|param|query|user)`),
			Antipattern: regexp.MustCompile(`filepath\.Clean`),
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-22",
			Fix:         "Use filepath.Clean() and validate the resolved path is within the expected directory",
		},
		{
			ID:          "SEC-GO-004",
			Name:        "Hardcoded Secret",
			Description: "Hardcoded password or secret string detected",
			Language:    "go",
			Pattern:     regexp.MustCompile(`(?i)(?:password|secret|api_?key|token|private_?key)\s*(?::?=|=)\s*"[^"]{4,}`),
			Antipattern: regexp.MustCompile(`(?i)(?:test|example|placeholder|TODO|CHANGE|xxx|dummy)`),
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-798",
			Fix:         "Use environment variables or a secrets manager instead of hardcoded credentials",
		},
		{
			ID:          "SEC-GO-005",
			Name:        "Insecure TLS",
			Description: "TLS certificate verification is disabled",
			Language:    "go",
			Pattern:     regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`),
			Antipattern: nil,
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-295",
			Fix:         "Remove InsecureSkipVerify: true; configure proper TLS certificate validation",
		},
		{
			ID:          "SEC-GO-006",
			Name:        "Weak Crypto (MD5)",
			Description: "MD5 is cryptographically broken and should not be used for security purposes",
			Language:    "go",
			Pattern:     regexp.MustCompile(`md5\.(?:New|Sum)`),
			Antipattern: regexp.MustCompile(`(?i)(?:checksum|fingerprint|cache|etag|non.?security)`),
			Severity:    "medium",
			Category:    "security",
			CWE:         "CWE-328",
			Fix:         "Use crypto/sha256 or crypto/sha512 instead of MD5 for security-sensitive operations",
		},
		{
			ID:          "SEC-GO-007",
			Name:        "Weak Crypto (SHA1)",
			Description: "SHA-1 is deprecated for security use; collisions are practical",
			Language:    "go",
			Pattern:     regexp.MustCompile(`sha1\.(?:New|Sum)`),
			Antipattern: regexp.MustCompile(`(?i)(?:git|fingerprint|cache|etag|non.?security)`),
			Severity:    "medium",
			Category:    "security",
			CWE:         "CWE-328",
			Fix:         "Use crypto/sha256 or crypto/sha512 instead of SHA-1 for security-sensitive operations",
		},
		{
			ID:          "SEC-GO-008",
			Name:        "Unvalidated Redirect",
			Description: "HTTP redirect using user-controlled input without validation",
			Language:    "go",
			Pattern:     regexp.MustCompile(`http\.Redirect\s*\(.*(?:r\.(?:URL|Form|Query)|req\.|param|input)`),
			Antipattern: nil,
			Severity:    "medium",
			Category:    "security",
			CWE:         "CWE-601",
			Fix:         "Validate redirect URLs against an allowlist of permitted destinations",
		},
		{
			ID:          "SEC-GO-009",
			Name:        "Sensitive Data in Log",
			Description: "Potentially logging sensitive data (passwords, tokens, secrets)",
			Language:    "go",
			Pattern:     regexp.MustCompile(`(?:log\.|slog\.|logger\.)(?:Print|Info|Debug|Warn|Error|Fatal).*(?i)(?:password|token|secret|key|credential)`),
			Antipattern: regexp.MustCompile(`(?i)(?:redact|mask|\*\*\*|<hidden>)`),
			Severity:    "medium",
			Category:    "security",
			CWE:         "CWE-532",
			Fix:         "Redact sensitive values before logging; never log passwords, tokens, or API keys",
		},
		{
			ID:          "SEC-GO-010",
			Name:        "Defer in Loop",
			Description: "defer inside a loop can accumulate resources until the function returns",
			Language:    "go",
			Pattern:     regexp.MustCompile(`^\s*defer\s+`),
			Antipattern: nil,
			Severity:    "medium",
			Category:    "correctness",
			CWE:         "",
			Fix:         "Move the deferred call into a helper function or handle resource cleanup explicitly in the loop",
		},
		// =====================================================================
		// SECURITY - Python
		// =====================================================================
		{
			ID:          "SEC-PY-001",
			Name:        "SQL Injection (f-string)",
			Description: "f-string used in SQL query construction; use parameterized queries",
			Language:    "python",
			Pattern:     regexp.MustCompile(`f["'](?:[^"']*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"']*)\{`),
			Antipattern: nil,
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-89",
			Fix:         "Use parameterized queries with %s or ? placeholders passed as a tuple",
		},
		{
			ID:          "SEC-PY-002",
			Name:        "eval() Usage",
			Description: "eval() executes arbitrary code and is a common injection vector",
			Language:    "python",
			Pattern:     regexp.MustCompile(`\beval\s*\(`),
			Antipattern: regexp.MustCompile(`(?i)(?:#.*safe|#.*trusted|ast\.literal_eval)`),
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-95",
			Fix:         "Use ast.literal_eval() for data parsing or find a safer alternative to eval()",
		},
		{
			ID:          "SEC-PY-003",
			Name:        "exec() Usage",
			Description: "exec() executes arbitrary code strings and is dangerous with user input",
			Language:    "python",
			Pattern:     regexp.MustCompile(`\bexec\s*\(`),
			Antipattern: nil,
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-95",
			Fix:         "Avoid exec(); use structured approaches like importlib or predefined function dispatch",
		},
		{
			ID:          "SEC-PY-004",
			Name:        "Pickle Deserialization",
			Description: "pickle.loads() can execute arbitrary code during deserialization",
			Language:    "python",
			Pattern:     regexp.MustCompile(`pickle\.loads?\s*\(`),
			Antipattern: nil,
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-502",
			Fix:         "Use JSON or another safe serialization format; if pickle is required, only load from trusted sources",
		},
		{
			ID:          "SEC-PY-005",
			Name:        "Subprocess Shell Injection",
			Description: "subprocess with shell=True is vulnerable to shell injection",
			Language:    "python",
			Pattern:     regexp.MustCompile(`subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True`),
			Antipattern: nil,
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-78",
			Fix:         "Use shell=False (default) and pass command as a list instead of a string",
		},
		{
			ID:          "SEC-PY-006",
			Name:        "Assert in Production",
			Description: "assert statements are stripped with -O flag; do not use for validation",
			Language:    "python",
			Pattern:     regexp.MustCompile(`^\s*assert\s+`),
			Antipattern: regexp.MustCompile(`(?i)(?:test_|_test\.py|conftest|pytest)`),
			Severity:    "low",
			Category:    "correctness",
			CWE:         "CWE-617",
			Fix:         "Replace assert with explicit validation that raises an appropriate exception",
		},
		{
			ID:          "SEC-PY-007",
			Name:        "Hardcoded Secret (Python)",
			Description: "Hardcoded password or secret string detected",
			Language:    "python",
			Pattern:     regexp.MustCompile(`(?i)(?:password|secret|api_?key|token|private_?key)\s*=\s*["'][^"']{4,}["']`),
			Antipattern: regexp.MustCompile(`(?i)(?:test|example|placeholder|TODO|CHANGE|xxx|dummy|fake)`),
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-798",
			Fix:         "Use environment variables or a secrets manager instead of hardcoded credentials",
		},
		{
			ID:          "SEC-PY-008",
			Name:        "YAML Unsafe Load",
			Description: "yaml.load() without SafeLoader can execute arbitrary Python objects",
			Language:    "python",
			Pattern:     regexp.MustCompile(`yaml\.load\s*\(`),
			Antipattern: regexp.MustCompile(`Loader\s*=\s*(?:yaml\.)?SafeLoader`),
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-502",
			Fix:         "Use yaml.safe_load() or pass Loader=yaml.SafeLoader explicitly",
		},
		// =====================================================================
		// SECURITY - TypeScript/JavaScript
		// =====================================================================
		{
			ID:          "SEC-TS-001",
			Name:        "innerHTML Assignment",
			Description: "Direct innerHTML assignment enables XSS attacks",
			Language:    "typescript",
			Pattern:     regexp.MustCompile(`\.innerHTML\s*=`),
			Antipattern: regexp.MustCompile(`(?i)(?:sanitize|DOMPurify|escape)`),
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-79",
			Fix:         "Use textContent for plain text or a sanitization library (DOMPurify) for HTML",
		},
		{
			ID:          "SEC-JS-001",
			Name:        "innerHTML Assignment",
			Description: "Direct innerHTML assignment enables XSS attacks",
			Language:    "javascript",
			Pattern:     regexp.MustCompile(`\.innerHTML\s*=`),
			Antipattern: regexp.MustCompile(`(?i)(?:sanitize|DOMPurify|escape)`),
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-79",
			Fix:         "Use textContent for plain text or a sanitization library (DOMPurify) for HTML",
		},
		{
			ID:          "SEC-TS-002",
			Name:        "eval() Usage",
			Description: "eval() executes arbitrary code and is a common injection vector",
			Language:    "typescript",
			Pattern:     regexp.MustCompile(`\beval\s*\(`),
			Antipattern: nil,
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-95",
			Fix:         "Use JSON.parse() for data or Function constructor with extreme caution",
		},
		{
			ID:          "SEC-JS-002",
			Name:        "eval() Usage",
			Description: "eval() executes arbitrary code and is a common injection vector",
			Language:    "javascript",
			Pattern:     regexp.MustCompile(`\beval\s*\(`),
			Antipattern: nil,
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-95",
			Fix:         "Use JSON.parse() for data or Function constructor with extreme caution",
		},
		{
			ID:          "SEC-TS-003",
			Name:        "Prototype Pollution",
			Description: "__proto__ access can lead to prototype pollution attacks",
			Language:    "typescript",
			Pattern:     regexp.MustCompile(`__proto__`),
			Antipattern: regexp.MustCompile(`(?i)(?:hasOwnProperty|Object\.create\(null\))`),
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-1321",
			Fix:         "Use Object.create(null) for lookup objects or validate keys against __proto__, constructor, prototype",
		},
		{
			ID:          "SEC-JS-003",
			Name:        "Prototype Pollution",
			Description: "__proto__ access can lead to prototype pollution attacks",
			Language:    "javascript",
			Pattern:     regexp.MustCompile(`__proto__`),
			Antipattern: regexp.MustCompile(`(?i)(?:hasOwnProperty|Object\.create\(null\))`),
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-1321",
			Fix:         "Use Object.create(null) for lookup objects or validate keys against __proto__, constructor, prototype",
		},
		{
			ID:          "SEC-TS-004",
			Name:        "Regex DoS",
			Description: "Complex regex with nested quantifiers may be vulnerable to ReDoS",
			Language:    "typescript",
			Pattern:     regexp.MustCompile(`(?:new RegExp|/)\s*.*(?:\+\+|\*\*|\{\d+,\}.*\{\d+,\}|(?:\.\*){2,}|\([^)]*\+\)[^)]*\+)`),
			Antipattern: nil,
			Severity:    "medium",
			Category:    "security",
			CWE:         "CWE-1333",
			Fix:         "Simplify regex; add bounds to quantifiers; consider using re2 or a timeout",
		},
		{
			ID:          "SEC-JS-004",
			Name:        "Regex DoS",
			Description: "Complex regex with nested quantifiers may be vulnerable to ReDoS",
			Language:    "javascript",
			Pattern:     regexp.MustCompile(`(?:new RegExp|/)\s*.*(?:\+\+|\*\*|\{\d+,\}.*\{\d+,\}|(?:\.\*){2,}|\([^)]*\+\)[^)]*\+)`),
			Antipattern: nil,
			Severity:    "medium",
			Category:    "security",
			CWE:         "CWE-1333",
			Fix:         "Simplify regex; add bounds to quantifiers; consider using re2 or a timeout",
		},
		{
			ID:          "SEC-TS-005",
			Name:        "Hardcoded Secret (TS)",
			Description: "Hardcoded password or secret string detected",
			Language:    "typescript",
			Pattern:     regexp.MustCompile(`(?i)(?:password|secret|api_?key|token|private_?key)\s*[=:]\s*["'][^"']{4,}["']`),
			Antipattern: regexp.MustCompile(`(?i)(?:test|example|placeholder|TODO|CHANGE|xxx|dummy|process\.env|import)`),
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-798",
			Fix:         "Use environment variables or a secrets manager instead of hardcoded credentials",
		},
		{
			ID:          "SEC-JS-005",
			Name:        "Hardcoded Secret (JS)",
			Description: "Hardcoded password or secret string detected",
			Language:    "javascript",
			Pattern:     regexp.MustCompile(`(?i)(?:password|secret|api_?key|token|private_?key)\s*[=:]\s*["'][^"']{4,}["']`),
			Antipattern: regexp.MustCompile(`(?i)(?:test|example|placeholder|TODO|CHANGE|xxx|dummy|process\.env|import)`),
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-798",
			Fix:         "Use environment variables or a secrets manager instead of hardcoded credentials",
		},
		// =====================================================================
		// CORRECTNESS - Go
		// =====================================================================
		{
			ID:          "COR-GO-001",
			Name:        "Unchecked Error",
			Description: "Function return value that likely includes an error is discarded",
			Language:    "go",
			Pattern:     regexp.MustCompile(`^\s*[a-zA-Z_][a-zA-Z0-9_.]*\s*\(.*\)\s*$`),
			Antipattern: regexp.MustCompile(`(?:^//|^\s*//|defer|go\s+|fmt\.Print|log\.|println|print\()`),
			Severity:    "medium",
			Category:    "correctness",
			CWE:         "CWE-252",
			Fix:         "Capture and handle the returned error: if err != nil { return err }",
		},
		{
			ID:          "COR-GO-002",
			Name:        "Goroutine Leak Risk",
			Description: "Goroutine launched without visible context cancellation or done channel",
			Language:    "go",
			Pattern:     regexp.MustCompile(`\bgo\s+func\s*\(`),
			Antipattern: regexp.MustCompile(`(?:ctx|context|done|cancel|Done\(\)|quit|stop|timer|ticker)`),
			Severity:    "medium",
			Category:    "correctness",
			CWE:         "",
			Fix:         "Pass a context.Context or done channel to goroutines to enable graceful shutdown",
		},
		{
			ID:          "COR-GO-003",
			Name:        "Race Condition Risk",
			Description: "Shared variable access in goroutine without synchronization",
			Language:    "go",
			Pattern:     regexp.MustCompile(`go\s+func\s*\([^)]*\)\s*\{[^}]*(?:[a-z]+\s*(?:\+\+|--|(?:\+|-|\*|/)=))`),
			Antipattern: regexp.MustCompile(`(?:mutex|Mutex|sync\.|atomic\.|Lock\(\)|chan\s)`),
			Severity:    "high",
			Category:    "correctness",
			CWE:         "CWE-362",
			Fix:         "Use sync.Mutex, sync/atomic, or channels to synchronize shared state access",
		},
		{
			ID:          "COR-GO-004",
			Name:        "nil Map Write",
			Description: "Writing to a potentially nil map causes a runtime panic",
			Language:    "go",
			Pattern:     regexp.MustCompile(`var\s+\w+\s+map\[`),
			Antipattern: regexp.MustCompile(`=\s*(?:make|map\[)`),
			Severity:    "high",
			Category:    "correctness",
			CWE:         "",
			Fix:         "Initialize the map with make() before writing to it",
		},
		// =====================================================================
		// PERFORMANCE
		// =====================================================================
		{
			ID:          "PERF-GO-001",
			Name:        "String Concat in Loop",
			Description: "String concatenation with += in a loop causes quadratic allocation",
			Language:    "go",
			Pattern:     regexp.MustCompile(`\w+\s*\+=\s*(?:"|\w+)`),
			Antipattern: regexp.MustCompile(`(?:int|float|byte|rune|uint|count|total|sum|num|idx|index|offset|i\s*\+)`),
			Severity:    "low",
			Category:    "performance",
			CWE:         "",
			Fix:         "Use strings.Builder for string concatenation in loops",
		},
		{
			ID:          "PERF-GO-002",
			Name:        "Unbounded Allocation",
			Description: "Slice allocation with user-controlled size without bounds check",
			Language:    "go",
			Pattern:     regexp.MustCompile(`make\s*\(\s*\[\]\w+\s*,\s*(?:req\.|r\.|input|param|query|size|length|count|n\b)`),
			Antipattern: regexp.MustCompile(`(?:maxSize|maxLen|cap|min\(|max\(|limit|<=|>=|<\s*\d|>\s*\d)`),
			Severity:    "medium",
			Category:    "performance",
			CWE:         "CWE-789",
			Fix:         "Validate and cap allocation sizes to prevent denial of service via memory exhaustion",
		},
		{
			ID:          "PERF-GO-003",
			Name:        "N+1 Query Pattern",
			Description: "Database query inside a loop suggests N+1 query problem",
			Language:    "go",
			Pattern:     regexp.MustCompile(`(?:\.Query|\.Exec|\.Get|\.Find|\.First|\.Select|\.Where)\s*\(`),
			Antipattern: regexp.MustCompile(`(?:batch|bulk|IN\s*\(|ids|Preload|Join)`),
			Severity:    "medium",
			Category:    "performance",
			CWE:         "",
			Fix:         "Batch database queries outside the loop; use IN clauses or JOINs",
		},
		{
			ID:          "PERF-PY-001",
			Name:        "N+1 Query Pattern (Python)",
			Description: "Database query inside a loop suggests N+1 query problem",
			Language:    "python",
			Pattern:     regexp.MustCompile(`(?:\.execute|\.query|\.filter|\.get|session\.)\s*\(`),
			Antipattern: regexp.MustCompile(`(?:bulk|batch|in_|prefetch|select_related|join)`),
			Severity:    "medium",
			Category:    "performance",
			CWE:         "",
			Fix:         "Use select_related/prefetch_related (Django) or eager loading (SQLAlchemy) to batch queries",
		},
		{
			ID:          "PERF-ANY-001",
			Name:        "Synchronous Sleep",
			Description: "Hardcoded sleep/delay found; consider exponential backoff or event-driven approach",
			Language:    "any",
			Pattern:     regexp.MustCompile(`(?:time\.Sleep|sleep\(|setTimeout.*\d{4,}|Thread\.sleep)`),
			Antipattern: regexp.MustCompile(`(?i)(?:test|spec|mock|backoff|retry)`),
			Severity:    "low",
			Category:    "performance",
			CWE:         "",
			Fix:         "Use exponential backoff for retries or event-driven signaling instead of fixed sleeps",
		},
		// =====================================================================
		// SECURITY - Any Language
		// =====================================================================
		{
			ID:          "SEC-ANY-001",
			Name:        "TODO Security",
			Description: "TODO/FIXME/HACK comment related to security found in code",
			Language:    "any",
			Pattern:     regexp.MustCompile(`(?i)(?://|#|/\*)\s*(?:TODO|FIXME|HACK|XXX).*(?:security|auth|crypt|password|token|vuln|inject|xss|csrf)`),
			Antipattern: nil,
			Severity:    "medium",
			Category:    "security",
			CWE:         "",
			Fix:         "Address security-related TODOs before shipping; they indicate known unresolved issues",
		},
		{
			ID:          "SEC-ANY-002",
			Name:        "Private Key in Source",
			Description: "Private key material appears to be embedded in source code",
			Language:    "any",
			Pattern:     regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----`),
			Antipattern: regexp.MustCompile(`(?i)(?:test|example|sample|mock|fixture)`),
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-798",
			Fix:         "Remove private keys from source; load them from secure storage or environment at runtime",
		},
		{
			ID:          "SEC-ANY-003",
			Name:        "HTTP in Production",
			Description: "Insecure HTTP URL used where HTTPS should be expected",
			Language:    "any",
			Pattern:     regexp.MustCompile(`http://[a-zA-Z][a-zA-Z0-9._-]*`),
			Antipattern: regexp.MustCompile(`(?i)(?:http://localhost|http://127\.0\.0\.1|http://0\.0\.0\.0|http://\[?::1|http://example\.com|test|spec|mock|doc|xmlns|http://www\.w3\.org)`),
			Severity:    "low",
			Category:    "security",
			CWE:         "CWE-319",
			Fix:         "Use HTTPS for all production URLs to prevent man-in-the-middle attacks",
		},
	}
}
