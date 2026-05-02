package review

import "strings"

// CWEMapping maps a security finding pattern to a CWE identifier.
type CWEMapping struct {
	ID       string   // e.g. "CWE-89"
	Name     string   // e.g. "SQL Injection"
	Keywords []string // lowercase keywords to match in finding messages
}

// cweDatabase is the built-in set of common security weakness patterns.
var cweDatabase = []CWEMapping{
	{
		ID:       "CWE-89",
		Name:     "SQL Injection",
		Keywords: []string{"sql injection", "sql concat", "string concatenation into sql", "raw query", "unsanitized sql"},
	},
	{
		ID:       "CWE-79",
		Name:     "Cross-site Scripting (XSS)",
		Keywords: []string{"xss", "cross-site scripting", "unescaped output", "unsanitized html", "reflected input"},
	},
	{
		ID:       "CWE-78",
		Name:     "OS Command Injection",
		Keywords: []string{"command injection", "os.exec", "exec.command", "shell injection", "unsanitized command"},
	},
	{
		ID:       "CWE-22",
		Name:     "Path Traversal",
		Keywords: []string{"path traversal", "directory traversal", "../ ", "dot dot slash", "file path manipulation"},
	},
	{
		ID:       "CWE-918",
		Name:     "Server-Side Request Forgery (SSRF)",
		Keywords: []string{"ssrf", "server-side request forgery", "unvalidated url", "open redirect to internal"},
	},
	{
		ID:       "CWE-798",
		Name:     "Hardcoded Credentials",
		Keywords: []string{"hardcoded secret", "hardcoded password", "hardcoded credential", "hardcoded api key", "embedded secret", "secret in code"},
	},
	{
		ID:       "CWE-327",
		Name:     "Use of Broken Crypto Algorithm",
		Keywords: []string{"weak crypto", "md5", "sha1 ", "des ", "broken crypto", "insecure hash", "weak hash"},
	},
	{
		ID:       "CWE-502",
		Name:     "Deserialization of Untrusted Data",
		Keywords: []string{"insecure deserialization", "unsafe deserialization", "untrusted deserialization", "pickle", "yaml.load"},
	},
	{
		ID:       "CWE-611",
		Name:     "XML External Entity (XXE)",
		Keywords: []string{"xxe", "xml external entity", "xml injection"},
	},
	{
		ID:       "CWE-352",
		Name:     "Cross-Site Request Forgery (CSRF)",
		Keywords: []string{"csrf", "cross-site request forgery", "missing csrf token"},
	},
	{
		ID:       "CWE-200",
		Name:     "Information Exposure",
		Keywords: []string{"information disclosure", "sensitive data exposure", "data leak", "credential in log", "logging sensitive"},
	},
	{
		ID:       "CWE-362",
		Name:     "Race Condition",
		Keywords: []string{"race condition", "data race", "toctou", "time of check"},
	},
	{
		ID:       "CWE-190",
		Name:     "Integer Overflow",
		Keywords: []string{"integer overflow", "integer underflow", "int overflow"},
	},
	{
		ID:       "CWE-601",
		Name:     "Open Redirect",
		Keywords: []string{"open redirect", "url redirect", "unvalidated redirect"},
	},
	{
		ID:       "CWE-862",
		Name:     "Missing Authorization",
		Keywords: []string{"missing authorization", "missing auth check", "authorization bypass", "broken access control"},
	},
}

// MatchCWE checks a finding's message (and fix) against the CWE database and
// returns the CWE ID if a match is found. Returns empty string if no match.
func MatchCWE(message, fix string) string {
	lower := strings.ToLower(message + " " + fix)
	for _, cwe := range cweDatabase {
		for _, keyword := range cwe.Keywords {
			if strings.Contains(lower, keyword) {
				return cwe.ID
			}
		}
	}
	return ""
}

// LookupCWEName returns the human-readable name for a CWE ID.
func LookupCWEName(id string) string {
	for _, cwe := range cweDatabase {
		if cwe.ID == id {
			return cwe.Name
		}
	}
	return ""
}
