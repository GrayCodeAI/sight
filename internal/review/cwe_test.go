package review

import "testing"

func TestMatchCWE_SQLInjection(t *testing.T) {
	id := MatchCWE("SQL injection via string concatenation", "use parameterized query")
	if id != "CWE-89" {
		t.Errorf("expected CWE-89, got %q", id)
	}
}

func TestMatchCWE_XSS(t *testing.T) {
	id := MatchCWE("Cross-site scripting vulnerability in template", "")
	if id != "CWE-79" {
		t.Errorf("expected CWE-79, got %q", id)
	}
}

func TestMatchCWE_CommandInjection(t *testing.T) {
	id := MatchCWE("Command injection through exec.Command", "")
	if id != "CWE-78" {
		t.Errorf("expected CWE-78, got %q", id)
	}
}

func TestMatchCWE_PathTraversal(t *testing.T) {
	id := MatchCWE("Path traversal allows reading arbitrary files", "")
	if id != "CWE-22" {
		t.Errorf("expected CWE-22, got %q", id)
	}
}

func TestMatchCWE_SSRF(t *testing.T) {
	id := MatchCWE("SSRF vulnerability allows internal network access", "")
	if id != "CWE-918" {
		t.Errorf("expected CWE-918, got %q", id)
	}
}

func TestMatchCWE_HardcodedCredentials(t *testing.T) {
	id := MatchCWE("Hardcoded password found in configuration", "")
	if id != "CWE-798" {
		t.Errorf("expected CWE-798, got %q", id)
	}
}

func TestMatchCWE_WeakCrypto(t *testing.T) {
	id := MatchCWE("Using MD5 for password hashing", "")
	if id != "CWE-327" {
		t.Errorf("expected CWE-327, got %q", id)
	}
}

func TestMatchCWE_InsecureDeserialization(t *testing.T) {
	id := MatchCWE("Insecure deserialization of user input", "")
	if id != "CWE-502" {
		t.Errorf("expected CWE-502, got %q", id)
	}
}

func TestMatchCWE_XXE(t *testing.T) {
	id := MatchCWE("XML external entity injection", "")
	if id != "CWE-611" {
		t.Errorf("expected CWE-611, got %q", id)
	}
}

func TestMatchCWE_CSRF(t *testing.T) {
	id := MatchCWE("Missing CSRF token validation", "")
	if id != "CWE-352" {
		t.Errorf("expected CWE-352, got %q", id)
	}
}

func TestMatchCWE_InformationDisclosure(t *testing.T) {
	id := MatchCWE("Sensitive data exposure in API response", "")
	if id != "CWE-200" {
		t.Errorf("expected CWE-200, got %q", id)
	}
}

func TestMatchCWE_RaceCondition(t *testing.T) {
	id := MatchCWE("Race condition in concurrent map access", "")
	if id != "CWE-362" {
		t.Errorf("expected CWE-362, got %q", id)
	}
}

func TestMatchCWE_IntegerOverflow(t *testing.T) {
	id := MatchCWE("Integer overflow in size calculation", "")
	if id != "CWE-190" {
		t.Errorf("expected CWE-190, got %q", id)
	}
}

func TestMatchCWE_OpenRedirect(t *testing.T) {
	id := MatchCWE("Open redirect allows phishing", "")
	if id != "CWE-601" {
		t.Errorf("expected CWE-601, got %q", id)
	}
}

func TestMatchCWE_MissingAuth(t *testing.T) {
	id := MatchCWE("Missing authorization check on admin endpoint", "")
	if id != "CWE-862" {
		t.Errorf("expected CWE-862, got %q", id)
	}
}

func TestMatchCWE_NoMatch(t *testing.T) {
	id := MatchCWE("Variable name is too short", "rename to something descriptive")
	if id != "" {
		t.Errorf("expected empty string for non-security message, got %q", id)
	}
}

func TestMatchCWE_CaseInsensitive(t *testing.T) {
	id := MatchCWE("SQL INJECTION vulnerability", "")
	if id != "CWE-89" {
		t.Errorf("expected CWE-89 (case insensitive), got %q", id)
	}
}

func TestMatchCWE_MatchInFix(t *testing.T) {
	// The keyword is only in the fix, not the message
	id := MatchCWE("vulnerability found", "fix the sql injection by using parameterized queries")
	if id != "CWE-89" {
		t.Errorf("expected CWE-89 from fix field match, got %q", id)
	}
}

func TestMatchCWE_EmptyInputs(t *testing.T) {
	id := MatchCWE("", "")
	if id != "" {
		t.Errorf("expected empty string for empty inputs, got %q", id)
	}
}

func TestLookupCWEName_Known(t *testing.T) {
	tests := []struct {
		id       string
		expected string
	}{
		{"CWE-89", "SQL Injection"},
		{"CWE-79", "Cross-site Scripting (XSS)"},
		{"CWE-78", "OS Command Injection"},
		{"CWE-22", "Path Traversal"},
		{"CWE-918", "Server-Side Request Forgery (SSRF)"},
		{"CWE-798", "Hardcoded Credentials"},
		{"CWE-327", "Use of Broken Crypto Algorithm"},
		{"CWE-502", "Deserialization of Untrusted Data"},
		{"CWE-611", "XML External Entity (XXE)"},
		{"CWE-352", "Cross-Site Request Forgery (CSRF)"},
		{"CWE-200", "Information Exposure"},
		{"CWE-362", "Race Condition"},
		{"CWE-190", "Integer Overflow"},
		{"CWE-601", "Open Redirect"},
		{"CWE-862", "Missing Authorization"},
	}

	for _, tc := range tests {
		name := LookupCWEName(tc.id)
		if name != tc.expected {
			t.Errorf("LookupCWEName(%q): expected %q, got %q", tc.id, tc.expected, name)
		}
	}
}

func TestLookupCWEName_Unknown(t *testing.T) {
	name := LookupCWEName("CWE-9999")
	if name != "" {
		t.Errorf("expected empty string for unknown CWE, got %q", name)
	}
}

func TestLookupCWEName_Empty(t *testing.T) {
	name := LookupCWEName("")
	if name != "" {
		t.Errorf("expected empty string for empty ID, got %q", name)
	}
}
