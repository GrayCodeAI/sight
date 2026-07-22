package sight

import "regexp"

// javaSecurityRules returns built-in static analysis rules for Java.
func javaSecurityRules() []StaticRule {
	return []StaticRule{
		// =====================================================================
		// SECURITY - Java
		// =====================================================================
		{
			ID:          "SEC-JV-001",
			Name:        "SQL Injection (Java)",
			Description: "String concatenation used in SQL statement execution; use PreparedStatement instead",
			Language:    "java",
			Pattern:     regexp.MustCompile(`(?:(?:execute|executeQuery|executeUpdate)\s*\(.*\+)|(?:(?:Statement|createStatement).*\+)`),
			Antipattern: regexp.MustCompile(`PreparedStatement|setParameter|bindValue`),
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-89",
			Fix:         "Use PreparedStatement with parameter placeholders (?) instead of string concatenation",
		},
		{
			ID:          "SEC-JV-002",
			Name:        "Insecure Deserialization (Java)",
			Description: "ObjectInputStream.readObject() can execute arbitrary code during deserialization",
			Language:    "java",
			Pattern:     regexp.MustCompile(`ObjectInputStream.*\.readObject\s*\(`),
			Antipattern: regexp.MustCompile(`(?i)(?:ValidatingObjectInputStream|ObjectInputFilter|whiteList|allowList)`),
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-502",
			Fix:         "Use ValidatingObjectInputStream or an ObjectInputFilter with a strict allowlist",
		},
		{
			ID:          "SEC-JV-003",
			Name:        "SSRF (Java)",
			Description: "new URL() with user-controlled input may lead to Server-Side Request Forgery",
			Language:    "java",
			Pattern:     regexp.MustCompile(`new\s+URL\s*\(.*(?:req\.|request\.|param|input|query|user)`),
			Antipattern: regexp.MustCompile(`(?i)(?:allowList|whitelist|validate.*url|UriUtils)`),
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-918",
			Fix:         "Validate URLs against an allowlist of permitted domains and schemes",
		},
		{
			ID:          "SEC-JV-004",
			Name:        "Hardcoded Secret (Java)",
			Description: "Hardcoded password or secret string detected",
			Language:    "java",
			Pattern:     regexp.MustCompile(`(?i)(?:password|secret|api_?key|token|private_?key)\s*=\s*"[^"]{4,}"`),
			Antipattern: regexp.MustCompile(`(?i)(?:test|example|placeholder|TODO|CHANGE|xxx|dummy|fake|System\.getenv)`),
			Severity:    "critical",
			Category:    "security",
			CWE:         "CWE-798",
			Fix:         "Use environment variables, a secrets manager, or a vault instead of hardcoded credentials",
		},
		{
			ID:          "SEC-JV-005",
			Name:        "Path Traversal (Java)",
			Description: "new File() with user-controlled input may allow path traversal attacks",
			Language:    "java",
			Pattern:     regexp.MustCompile(`new\s+File\s*\(.*(?:req\.|request\.|param|input|query|user|\+)`),
			Antipattern: regexp.MustCompile(`(?i)(?:canonicalPath|normalize|sanitizePath|getCanonicalPath)`),
			Severity:    "high",
			Category:    "security",
			CWE:         "CWE-22",
			Fix:         "Validate and normalize paths; ensure the resolved path is within the expected directory",
		},
	}
}
