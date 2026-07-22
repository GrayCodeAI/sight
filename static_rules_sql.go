package sight

import "regexp"

// sqlSecurityRules returns built-in static analysis rules for SQL.
func sqlSecurityRules() []StaticRule {
	return []StaticRule{
		// =====================================================================
		// SECURITY - SQL
		// =====================================================================
		{
			ID:          "SEC-SQL-001",
			Name:        "DROP TABLE in Migration",
			Description: "DROP TABLE statement found; data loss is irreversible without backup",
			Language:    "sql",
			Pattern:     regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`),
			Antipattern: regexp.MustCompile(`(?i)(?:IF\s+EXISTS|migration|rollback|revert)`),
			Severity:    "high",
			Category:    "security",
			CWE:         "",
			Fix:         "Use 'DROP TABLE IF EXISTS' and ensure a rollback migration exists; consider soft deletes",
		},
		{
			ID:          "SEC-SQL-002",
			Name:        "Always-True Condition",
			Description: "Tautological condition (1=1, OR 1=1) found; may indicate SQL injection or logic error",
			Language:    "sql",
			Pattern:     regexp.MustCompile(`(?i)\b(?:OR\s+1\s*=\s*1|AND\s+1\s*=\s*1)\b`),
			Antipattern: regexp.MustCompile(`(?i)(?:test|spec|mock)`),
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-89",
			Fix:         "Remove tautological conditions; if this is injection testing, use parameterized queries in production",
		},
		{
			ID:          "SEC-SQL-003",
			Name:        "UNION-Based Injection Pattern",
			Description: "UNION SELECT pattern may indicate SQL injection attack vector",
			Language:    "sql",
			Pattern:     regexp.MustCompile(`(?i)\bUNION\s+(?:ALL\s+)?SELECT\b`),
			Antipattern: regexp.MustCompile(`(?i)(?:test|spec|mock|migration)`),
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-89",
			Fix:         "Use parameterized queries; never concatenate user input into SQL statements",
		},
	}
}
