package sight

import "regexp"

// rubySecurityRules returns built-in static analysis rules for Ruby.
func rubySecurityRules() []StaticRule {
	return []StaticRule{
		// =====================================================================
		// SECURITY - Ruby
		// =====================================================================
		{
			ID:          "SEC-RB-001",
			Name:        "SQL Injection (Ruby)",
			Description: "String interpolation in SQL query; use parameterized queries instead",
			Language:    "ruby",
			Pattern:     regexp.MustCompile(`(?:(?:\.where|\.find_by_sql|\.execute|\.query)\s*\(?\s*["'].*#\{)|(?:%[qQwWiI]?\{.*(?:SELECT|INSERT|UPDATE|DELETE).*#\{)`),
			Antipattern: nil,
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-89",
			Fix:         "Use parameterized queries: Model.where('id = ?', id) or ActiveRecord::sanitize_sql",
		},
		{
			ID:          "SEC-RB-002",
			Name:        "Command Injection (Ruby)",
			Description: "system(), exec(), or backtick command with user-controlled input",
			Language:    "ruby",
			Pattern:     regexp.MustCompile(`\b(?:system|exec|` + "`" + `)\s*[\(]?.*#\{`),
			Antipattern: nil,
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-78",
			Fix:         "Use Open3.capture2 or Kernel#system with separate arguments to avoid shell injection",
		},
		{
			ID:          "SEC-RB-003",
			Name:        "Mass Assignment",
			Description: "permit! or unfiltered params usage allows arbitrary attribute assignment",
			Language:    "ruby",
			Pattern:     regexp.MustCompile(`\.permit!|params\s*\[|params\.require\(.*\)\.permit\s*[^(\w]`),
			Antipattern: regexp.MustCompile(`\.permit\s*\(\s*[:\w]`),
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-915",
			Fix:         "Use strong parameters: params.require(:model).permit(:field1, :field2) with explicit allowlist",
		},
		{
			ID:          "SEC-RB-004",
			Name:        "Hardcoded Secret (Ruby)",
			Description: "Hardcoded password or secret string detected",
			Language:    "ruby",
			Pattern:     regexp.MustCompile(`(?i)(?:password|secret|api_?key|token|private_?key)\s*=\s*['"][^'"]{4,}['"]`),
			Antipattern: regexp.MustCompile(`(?i)(?:test|example|placeholder|TODO|CHANGE|xxx|dummy|fake|ENV\[)`),
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-798",
			Fix:         "Use ENV['VAR_NAME'], Rails credentials, or a secrets manager instead of hardcoded credentials",
		},
		{
			ID:          "SEC-RB-005",
			Name:        "ERB XSS",
			Description: "<%= %> tag without sanitization may render user content unsafely",
			Language:    "ruby",
			Pattern:     regexp.MustCompile(`<%=\s*`),
			Antipattern: regexp.MustCompile(`(?i)(?:h\(|html_escape|sanitize|escape_javascript|CGI\.escape)`),
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-79",
			Fix:         "Use <%=h ... %> or <%= sanitize(...) %> to escape user content in ERB templates",
		},
	}
}
