package sight

import (
	"strings"
	"testing"
)

func TestNewStaticAnalyzer(t *testing.T) {
	sa := NewStaticAnalyzer()
	if sa == nil {
		t.Fatal("NewStaticAnalyzer returned nil")
	}
	if len(sa.Rules) < 50 {
		t.Errorf("expected at least 50 default rules, got %d", len(sa.Rules))
	}
}

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"main.go", "go"},
		{"app.py", "python"},
		{"index.ts", "typescript"},
		{"index.tsx", "typescript"},
		{"app.js", "javascript"},
		{"app.jsx", "javascript"},
		{"unknown.rb", "ruby"},
		{"path/to/File.GO", "go"},
		{"lib.rs", "rust"},
		{"Main.java", "java"},
		{"main.c", "c"},
		{"main.h", "c"},
		{"app.cpp", "cpp"},
		{"app.hpp", "cpp"},
		{"schema.sql", "sql"},
	}
	for _, tt := range tests {
		got := DetectLanguage(tt.path)
		if got != tt.want {
			t.Errorf("DetectLanguage(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

// --- Security Rules: Go ---

func TestGoSQLInjection(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)`
	findings := sa.AnalyzeFile(code, "go")
	assertHasFinding(t, findings, "SEC-GO-001", "SQL Injection")
}

func TestGoCommandInjection(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `cmd := exec.Command(userInput)`
	findings := sa.AnalyzeFile(code, "go")
	assertHasFinding(t, findings, "SEC-GO-002", "Command Injection")
}

func TestGoCommandInjection_SafeCase(t *testing.T) {
	sa := NewStaticAnalyzer()
	// Static command string is fine
	code := `cmd := exec.Command("ls")`
	findings := sa.AnalyzeFile(code, "go")
	assertNoFinding(t, findings, "SEC-GO-002")
}

func TestGoPathTraversal(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `f, err := os.Open(req.URL.Query().Get("file"))`
	findings := sa.AnalyzeFile(code, "go")
	assertHasFinding(t, findings, "SEC-GO-003", "Path Traversal")
}

func TestGoPathTraversal_Clean(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `f, err := os.Open(filepath.Clean(req.URL.Query().Get("file")))`
	findings := sa.AnalyzeFile(code, "go")
	assertNoFinding(t, findings, "SEC-GO-003")
}

func TestGoHardcodedSecret(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `password := "sup3rs3cr3t123"`
	findings := sa.AnalyzeFile(code, "go")
	assertHasFinding(t, findings, "SEC-GO-004", "Hardcoded Secret")
}

func TestGoHardcodedSecret_TestValue(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `password := "test-placeholder-value"`
	findings := sa.AnalyzeFile(code, "go")
	assertNoFinding(t, findings, "SEC-GO-004")
}

func TestGoInsecureTLS(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `tlsConfig := &tls.Config{InsecureSkipVerify: true}`
	findings := sa.AnalyzeFile(code, "go")
	assertHasFinding(t, findings, "SEC-GO-005", "Insecure TLS")
}

func TestGoWeakCryptoMD5(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `h := md5.New()`
	findings := sa.AnalyzeFile(code, "go")
	assertHasFinding(t, findings, "SEC-GO-006", "Weak Crypto")
}

func TestGoWeakCryptoSHA1(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `h := sha1.New()`
	findings := sa.AnalyzeFile(code, "go")
	assertHasFinding(t, findings, "SEC-GO-007", "Weak Crypto")
}

func TestGoSensitiveLog(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `log.Printf("user login: password=%s", pw)`
	findings := sa.AnalyzeFile(code, "go")
	assertHasFinding(t, findings, "SEC-GO-009", "Sensitive Data in Log")
}

// --- Security Rules: Python ---

func TestPythonSQLInjection(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
	findings := sa.AnalyzeFile(code, "python")
	assertHasFinding(t, findings, "SEC-PY-001", "SQL Injection")
}

func TestPythonEval(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `result = eval(user_input)`
	findings := sa.AnalyzeFile(code, "python")
	assertHasFinding(t, findings, "SEC-PY-002", "eval()")
}

func TestPythonExec(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `exec(code_string)`
	findings := sa.AnalyzeFile(code, "python")
	assertHasFinding(t, findings, "SEC-PY-003", "exec()")
}

func TestPythonPickle(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `data = pickle.loads(payload)`
	findings := sa.AnalyzeFile(code, "python")
	assertHasFinding(t, findings, "SEC-PY-004", "Pickle Deserialization")
}

func TestPythonSubprocessShell(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `subprocess.call(cmd, shell=True)`
	findings := sa.AnalyzeFile(code, "python")
	assertHasFinding(t, findings, "SEC-PY-005", "Subprocess Shell Injection")
}

func TestPythonAssert(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `assert user.is_admin`
	findings := sa.AnalyzeFile(code, "python")
	assertHasFinding(t, findings, "SEC-PY-006", "Assert in Production")
}

func TestPythonYAMLUnsafe(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `data = yaml.load(content)`
	findings := sa.AnalyzeFile(code, "python")
	assertHasFinding(t, findings, "SEC-PY-008", "YAML Unsafe Load")
}

func TestPythonYAMLSafe(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `data = yaml.load(content, Loader=yaml.SafeLoader)`
	findings := sa.AnalyzeFile(code, "python")
	assertNoFinding(t, findings, "SEC-PY-008")
}

// --- Security Rules: TypeScript/JavaScript ---

func TestTSInnerHTML(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `element.innerHTML = userInput`
	findings := sa.AnalyzeFile(code, "typescript")
	assertHasFinding(t, findings, "SEC-TS-001", "innerHTML")
}

func TestTSInnerHTML_Sanitized(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `element.innerHTML = DOMPurify.sanitize(userInput)`
	findings := sa.AnalyzeFile(code, "typescript")
	assertNoFinding(t, findings, "SEC-TS-001")
}

func TestJSInnerHTML(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `element.innerHTML = userInput`
	findings := sa.AnalyzeFile(code, "javascript")
	assertHasFinding(t, findings, "SEC-JS-001", "innerHTML")
}

func TestTSEval(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `const result = eval(expression)`
	findings := sa.AnalyzeFile(code, "typescript")
	assertHasFinding(t, findings, "SEC-TS-002", "eval()")
}

func TestTSPrototypePollution(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `obj[key].__proto__ = malicious`
	findings := sa.AnalyzeFile(code, "typescript")
	assertHasFinding(t, findings, "SEC-TS-003", "Prototype Pollution")
}

func TestJSPrototypePollution(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `obj.__proto__.polluted = true`
	findings := sa.AnalyzeFile(code, "javascript")
	assertHasFinding(t, findings, "SEC-JS-003", "Prototype Pollution")
}

// --- Correctness Rules: Go ---

func TestGoGoroutineLeak(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `go func() { doWork() }()`
	findings := sa.AnalyzeFile(code, "go")
	assertHasFinding(t, findings, "COR-GO-002", "Goroutine Leak")
}

func TestGoGoroutineLeak_WithContext(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `go func(ctx context.Context) { doWork(ctx) }(ctx)`
	findings := sa.AnalyzeFile(code, "go")
	assertNoFinding(t, findings, "COR-GO-002")
}

func TestGoNilMap(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `var cache map[string]int`
	findings := sa.AnalyzeFile(code, "go")
	assertHasFinding(t, findings, "COR-GO-004", "nil Map Write")
}

// --- Performance Rules ---

func TestGoUnboundedAlloc(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `items := make([]byte, req.ContentLength)`
	findings := sa.AnalyzeFile(code, "go")
	assertHasFinding(t, findings, "PERF-GO-002", "Unbounded Allocation")
}

func TestGoNPlusOneQuery(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `row := db.Query("SELECT name FROM items WHERE id = ?")`
	findings := sa.AnalyzeFile(code, "go")
	assertHasFinding(t, findings, "PERF-GO-003", "N+1 Query")
}

// --- Any Language Rules ---

func TestTodoSecurity(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `// TODO: fix authentication bypass vulnerability`
	findings := sa.AnalyzeFile(code, "any")
	assertHasFinding(t, findings, "SEC-ANY-001", "TODO Security")
}

func TestPrivateKey(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `key := "-----BEGIN RSA PRIVATE KEY-----"`
	findings := sa.AnalyzeFile(code, "any")
	assertHasFinding(t, findings, "SEC-ANY-002", "Private Key")
}

func TestHTTPInsecure(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `url := "http://api.production.example.org/v1/data"`
	findings := sa.AnalyzeFile(code, "any")
	assertHasFinding(t, findings, "SEC-ANY-003", "HTTP in Production")
}

func TestHTTPLocalhost_OK(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `url := "http://localhost:8080/health"`
	findings := sa.AnalyzeFile(code, "any")
	assertNoFinding(t, findings, "SEC-ANY-003")
}

// --- Diff-based Analysis ---

func TestAnalyzeDiff(t *testing.T) {
	sa := NewStaticAnalyzer()
	diff := `--- a/main.go
+++ b/main.go
@@ -10,6 +10,8 @@ func handler(w http.ResponseWriter, r *http.Request) {
     name := r.URL.Query().Get("name")
+    query := fmt.Sprintf("SELECT * FROM users WHERE name = %s", name)
+    rows, err := db.Query(query)
     if err != nil {
         log.Fatal(err)
     }
`
	findings := sa.Analyze(diff, "go")
	assertHasFinding(t, findings, "SEC-GO-001", "SQL Injection")

	// Check line number is correct (line 11 in new file)
	for _, f := range findings {
		if strings.Contains(f.Message, "SEC-GO-001") {
			if f.Line != 11 {
				t.Errorf("expected line 11, got %d", f.Line)
			}
			if f.File != "main.go" {
				t.Errorf("expected file main.go, got %q", f.File)
			}
			break
		}
	}
}

func TestAnalyzeDiff_NoFalsePositives(t *testing.T) {
	sa := NewStaticAnalyzer()
	// Context lines (without +) should not trigger rules
	diff := `--- a/main.go
+++ b/main.go
@@ -10,6 +10,7 @@ func handler() {
     query := fmt.Sprintf("SELECT * FROM users WHERE name = %s", name)
+    // Added a comment
     rows, err := db.Query(query)
`
	findings := sa.Analyze(diff, "go")
	// The SQL injection line is context (no +), so it should not be flagged
	assertNoFinding(t, findings, "SEC-GO-001")
}

func TestAnalyzeDiff_MultipleFiles(t *testing.T) {
	sa := NewStaticAnalyzer()
	diff := `--- a/auth.go
+++ b/auth.go
@@ -5,3 +5,4 @@ func login() {
     user := getUser()
+    password := "hardcoded_secret_value"
     return user
--- a/config.go
+++ b/config.go
@@ -1,3 +1,4 @@ package config
 var Debug = false
+var TLSConfig = &tls.Config{InsecureSkipVerify: true}
 var Port = 8080
`
	findings := sa.Analyze(diff, "go")
	assertHasFinding(t, findings, "SEC-GO-004", "Hardcoded Secret")
	assertHasFinding(t, findings, "SEC-GO-005", "Insecure TLS")
}

func TestAnalyzeFile_LanguageFilter(t *testing.T) {
	sa := NewStaticAnalyzer()
	// Python rule should not fire for Go code
	code := `result = eval(user_input)`
	findings := sa.AnalyzeFile(code, "go")
	assertNoFinding(t, findings, "SEC-PY-002")
}

func TestAnalyzeFileWithPath(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `password := "my_secret_pass"`
	findings := sa.AnalyzeFileWithPath(code, "go", "internal/auth/config.go")
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	if findings[0].File != "internal/auth/config.go" {
		t.Errorf("expected file path set, got %q", findings[0].File)
	}
}

func TestAnalyzeFile_FindingSeverity(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `tlsConfig := &tls.Config{InsecureSkipVerify: true}`
	findings := sa.AnalyzeFile(code, "go")
	for _, f := range findings {
		if strings.Contains(f.Message, "SEC-GO-005") {
			if f.Severity != SeverityHigh {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
			return
		}
	}
	t.Error("SEC-GO-005 finding not found")
}

func TestAnalyzeFile_FindingCWE(t *testing.T) {
	sa := NewStaticAnalyzer()
	code := `query := fmt.Sprintf("SELECT id FROM t WHERE x = %s", v)`
	findings := sa.AnalyzeFile(code, "go")
	for _, f := range findings {
		if strings.Contains(f.Message, "SEC-GO-001") {
			if f.CWE != "CWE-89" {
				t.Errorf("expected CWE-89, got %q", f.CWE)
			}
			return
		}
	}
	t.Error("SEC-GO-001 finding not found")
}

func TestParseHunkNewStart(t *testing.T) {
	tests := []struct {
		header string
		want   int
	}{
		{"@@ -10,6 +10,8 @@ func foo() {", 10},
		{"@@ -1,3 +1,4 @@ package config", 1},
		{"@@ -0,0 +1,25 @@", 1},
		{"@@ -100,5 +200,7 @@", 200},
	}
	for _, tt := range tests {
		got := parseHunkNewStart(tt.header)
		if got != tt.want {
			t.Errorf("parseHunkNewStart(%q) = %d, want %d", tt.header, got, tt.want)
		}
	}
}

// --- Helpers ---

func assertHasFinding(t *testing.T, findings []Finding, ruleID, nameSubstring string) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f.Message, ruleID) {
			return
		}
	}
	t.Errorf("expected finding with rule %s (%s) but none found in %d findings", ruleID, nameSubstring, len(findings))
	for _, f := range findings {
		t.Logf("  found: %s", f.Message)
	}
}

func assertNoFinding(t *testing.T, findings []Finding, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f.Message, ruleID) {
			t.Errorf("unexpected finding with rule %s: %s", ruleID, f.Message)
			return
		}
	}
}
