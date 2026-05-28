package sight

import (
	"strings"
	"testing"
)

func TestNewTaintAnalyzer(t *testing.T) {
	ta := NewTaintAnalyzer()
	if ta == nil {
		t.Fatal("NewTaintAnalyzer returned nil")
	}
}

// ---------------------------------------------------------------------------
// SQL Injection via parameter → query
// ---------------------------------------------------------------------------

func TestTaintSQLInjection_ParameterToQuery(t *testing.T) {
	ta := NewTaintAnalyzer()
	diff := `diff --git a/handler.go b/handler.go
--- a/handler.go
+++ b/handler.go
@@ -10,0 +11,5 @@
+func getUser(w http.ResponseWriter, r *http.Request) {
+    id := r.URL.Query().Get("id")
+    query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
+    db.Query(query)
+}
`
	findings := ta.AnalyzeDiff(diff)
	if len(findings) == 0 {
		t.Fatal("expected at least one taint finding for SQL injection, got none")
	}

	found := false
	for _, f := range findings {
		if f.CWE == "CWE-89" && strings.Contains(f.File, "handler.go") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("expected critical severity for SQL injection, got %v", f.Severity)
			}
			t.Logf("Found SQL injection finding: %s", f.Message)
		}
	}
	if !found {
		t.Error("expected CWE-89 (SQL injection) finding")
	}
}

func TestTaintSQLInjection_SprintfDirect(t *testing.T) {
	ta := NewTaintAnalyzer()
	diff := `diff --git a/db.go b/db.go
--- a/db.go
+++ b/db.go
@@ -10,0 +11,3 @@
+func query(r *http.Request) {
+    q := fmt.Sprintf("SELECT * FROM t WHERE name='%s'", r.FormValue("name"))
+    db.Query(q)
+}
`
	findings := ta.AnalyzeDiff(diff)
	found := false
	for _, f := range findings {
		if f.CWE == "CWE-89" {
			found = true
		}
	}
	if !found {
		t.Error("expected CWE-89 finding for FormValue → SQL query")
	}
}

// ---------------------------------------------------------------------------
// Command Injection via parameter → exec
// ---------------------------------------------------------------------------

func TestTaintCommandInjection_ParameterToExec(t *testing.T) {
	ta := NewTaintAnalyzer()
	diff := `diff --git a/run.go b/run.go
--- a/run.go
+++ b/run.go
@@ -10,0 +11,4 @@
+func runCmd(cmd string) {
+    output, err := exec.Command(cmd)
+    _ = output
+}
`
	findings := ta.AnalyzeDiff(diff)
	found := false
	for _, f := range findings {
		if f.CWE == "CWE-78" && strings.Contains(f.File, "run.go") {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("expected critical severity for command injection, got %v", f.Severity)
			}
			t.Logf("Found command injection finding: %s", f.Message)
		}
	}
	if !found {
		t.Error("expected CWE-78 (command injection) finding")
	}
}

func TestTaintCommandInjection_EnvVarToExec(t *testing.T) {
	ta := NewTaintAnalyzer()
	diff := `diff --git a/run.go b/run.go
--- a/run.go
+++ b/run.go
@@ -10,0 +11,3 @@
+func doExec() {
+    cmd := os.Getenv("CMD")
+    exec.Command(cmd)
+}
`
	findings := ta.AnalyzeDiff(diff)
	found := false
	for _, f := range findings {
		if f.CWE == "CWE-78" {
			found = true
		}
	}
	if !found {
		t.Error("expected CWE-78 finding for os.Getenv → exec.Command")
	}
}

// ---------------------------------------------------------------------------
// Path Traversal via parameter → file open
// ---------------------------------------------------------------------------

func TestTaintPathTraversal_ParameterToFileOpen(t *testing.T) {
	ta := NewTaintAnalyzer()
	diff := `diff --git a/file.go b/file.go
--- a/file.go
+++ b/file.go
@@ -10,0 +11,3 @@
+func readFile(filename string) {
+    content, _ := os.ReadFile(filename)
+}
`
	findings := ta.AnalyzeDiff(diff)
	found := false
	for _, f := range findings {
		if f.CWE == "CWE-22" && strings.Contains(f.File, "file.go") {
			found = true
			if f.Severity != SeverityHigh {
				t.Errorf("expected high severity for path traversal, got %v", f.Severity)
			}
			t.Logf("Found path traversal finding: %s", f.Message)
		}
	}
	if !found {
		t.Error("expected CWE-22 (path traversal) finding")
	}
}

func TestTaintPathTraversal_HTTPQueryToFile(t *testing.T) {
	ta := NewTaintAnalyzer()
	diff := `diff --git a/handler.go b/handler.go
--- a/handler.go
+++ b/handler.go
@@ -10,0 +11,3 @@
+func handler(r *http.Request) {
+    path := r.URL.Query().Get("file")
+    os.Open(path)
+}
`
	findings := ta.AnalyzeDiff(diff)
	found := false
	for _, f := range findings {
		if f.CWE == "CWE-22" {
			found = true
		}
	}
	if !found {
		t.Error("expected CWE-22 finding for HTTP query → os.Open")
	}
}

// ---------------------------------------------------------------------------
// Safe usage (parameter is sanitized before sink)
// ---------------------------------------------------------------------------

func TestTaintSafeUsage_SanitizedBeforeSink(t *testing.T) {
	ta := NewTaintAnalyzer()
	diff := `diff --git a/safe.go b/safe.go
--- a/safe.go
+++ b/safe.go
@@ -10,0 +11,5 @@
+func safeOpen(filename string) {
+    cleaned := filepath.Clean(filename)
+    content, _ := os.ReadFile(cleaned)
+    _ = content
+}
`
	findings := ta.AnalyzeDiff(diff)
	for _, f := range findings {
		if f.CWE == "CWE-22" && strings.Contains(f.File, "safe.go") {
			t.Errorf("expected no path traversal finding for sanitized input, but got: %s", f.Message)
		}
	}
}

func TestTaintSafeUsage_ConstantCommand(t *testing.T) {
	ta := NewTaintAnalyzer()
	diff := `diff --git a/safe.go b/safe.go
--- a/safe.go
+++ b/safe.go
@@ -10,0 +11,3 @@
+func doSomething() {
+    exec.Command("ls", "-la")
+}
`
	findings := ta.AnalyzeDiff(diff)
	for _, f := range findings {
		if f.CWE == "CWE-78" {
			t.Errorf("expected no command injection for constant command, but got: %s", f.Message)
		}
	}
}

// ---------------------------------------------------------------------------
// Propagation tests
// ---------------------------------------------------------------------------

func TestTaintPropagation_ThroughAssignment(t *testing.T) {
	ta := NewTaintAnalyzer()
	diff := `diff --git a/prop.go b/prop.go
--- a/prop.go
+++ b/prop.go
@@ -10,0 +11,5 @@
+func handle(name string) {
+    x := name
+    y := x
+    db.Query("SELECT * FROM t WHERE name='" + y + "'")
+}
`
	findings := ta.AnalyzeDiff(diff)
	found := false
	for _, f := range findings {
		if f.CWE == "CWE-89" {
			found = true
		}
	}
	if !found {
		t.Error("expected taint to propagate through assignments: name → x → y → query")
	}
}

func TestTaintPropagation_SprintfConcat(t *testing.T) {
	ta := NewTaintAnalyzer()
	diff := `diff --git a/prop.go b/prop.go
--- a/prop.go
+++ b/prop.go
@@ -10,0 +11,4 @@
+func handle(input string) {
+    query := fmt.Sprintf("SELECT * FROM t WHERE id=%s", input)
+    db.Query(query)
+}
`
	findings := ta.AnalyzeDiff(diff)
	found := false
	for _, f := range findings {
		if f.CWE == "CWE-89" {
			found = true
		}
	}
	if !found {
		t.Error("expected taint to flow through fmt.Sprintf to SQL query")
	}
}

// ---------------------------------------------------------------------------
// Source identification tests
// ---------------------------------------------------------------------------

func TestTaintSource_OsGetenv(t *testing.T) {
	ta := NewTaintAnalyzer()
	// Test AnalyzeSource directly with Go source containing os.Getenv → file open
	source := `package main

import (
	"os"
	"os/exec"
)

func main() {
	cmd := os.Getenv("CMD")
	exec.Command(cmd)
}
`
	findings := ta.AnalyzeSource(source, "main.go")
	found := false
	for _, f := range findings {
		if f.CWE == "CWE-78" {
			found = true
		}
	}
	if !found {
		t.Error("expected CWE-78 finding for os.Getenv → exec.Command via AnalyzeSource")
	}
}

func TestTaintSource_OsArgs(t *testing.T) {
	ta := NewTaintAnalyzer()
	source := `package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	cmd := os.Args[1]
	exec.Command(cmd)
}
`
	findings := ta.AnalyzeSource(source, "main.go")
	found := false
	for _, f := range findings {
		if f.CWE == "CWE-78" {
			found = true
		}
	}
	if !found {
		t.Error("expected CWE-78 finding for os.Args → exec.Command via AnalyzeSource")
	}
}

// ---------------------------------------------------------------------------
// Non-Go files should be skipped
// ---------------------------------------------------------------------------

func TestTaintSkipsNonGoFiles(t *testing.T) {
	ta := NewTaintAnalyzer()
	diff := `diff --git a/script.py b/script.py
--- a/script.py
+++ b/script.py
@@ -10,0 +11,2 @@
+def handler(input):
+    os.system(input)
`
	findings := ta.AnalyzeDiff(diff)
	if len(findings) != 0 {
		t.Errorf("expected no findings for Python file, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Empty diff
// ---------------------------------------------------------------------------

func TestTaintEmptyDiff(t *testing.T) {
	ta := NewTaintAnalyzer()
	findings := ta.AnalyzeDiff("")
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty diff, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Log leak with tainted data
// ---------------------------------------------------------------------------

func TestTaintLogLeak(t *testing.T) {
	ta := NewTaintAnalyzer()
	diff := `diff --git a/log.go b/log.go
--- a/log.go
+++ b/log.go
@@ -10,0 +11,3 @@
+func handle(token string) {
+    log.Println("token:", token)
+}
`
	findings := ta.AnalyzeDiff(diff)
	found := false
	for _, f := range findings {
		if f.CWE == "CWE-532" {
			found = true
		}
	}
	if !found {
		t.Error("expected CWE-532 (log leak) finding for parameter → log.Println")
	}
}

// ---------------------------------------------------------------------------
// AnalyzeSource tests (non-diff mode)
// ---------------------------------------------------------------------------

func TestTaintAnalyzeSource_SQLInjection(t *testing.T) {
	ta := NewTaintAnalyzer()
	source := `package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func handler(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
	db.Query(query)
}
`
	findings := ta.AnalyzeSource(source, "handler.go")
	found := false
	for _, f := range findings {
		if f.CWE == "CWE-89" {
			found = true
			t.Logf("Found: %s", f.Message)
		}
	}
	if !found {
		t.Error("expected CWE-89 finding via AnalyzeSource")
	}
}

func TestTaintAnalyzeSource_SafePath(t *testing.T) {
	ta := NewTaintAnalyzer()
	source := `package main

import (
	"os"
	"path/filepath"
)

func readFile(filename string) {
	cleaned := filepath.Clean(filename)
	os.ReadFile(cleaned)
}
`
	findings := ta.AnalyzeSource(source, "handler.go")
	for _, f := range findings {
		if f.CWE == "CWE-22" {
			t.Errorf("expected no path traversal for sanitized input, got: %s", f.Message)
		}
	}
}
