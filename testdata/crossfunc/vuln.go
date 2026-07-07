// Package vuln contains intentional cross-function taint flows used to exercise
// the SSA-based inter-procedural taint analyzer. The regex/diff analyzer cannot
// see these because the source and sink live in different functions.
package vuln

import (
	"database/sql"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

var db *sql.DB

// handler is the entry point: it reads untrusted input and passes it to other
// functions that contain the actual sinks.
func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	runQuery(name)
	runCmd(name)

	cfg := os.Getenv("CONFIG_PATH")
	readConfig(cfg)

	// Sanitized path must NOT be flagged: filepath.Clean neutralizes taint.
	safe := filepath.Clean(os.Getenv("SAFE_PATH"))
	_, _ = os.ReadFile(safe)

	_ = w
}

// runQuery builds a SQL statement from the tainted parameter (sink in a
// different function than the source).
func runQuery(q string) {
	// #nosec G202 — intentional test data for taint analysis
	query := "SELECT * FROM users WHERE name = '" + q + "'"
	_, _ = db.Query(query)
}

// runCmd executes a shell command with the tainted parameter.
func runCmd(c string) {
	_ = exec.Command("sh", "-c", c).Run()
}

// readConfig opens a file using the tainted path (path traversal sink).
func readConfig(path string) {
	_, _ = os.ReadFile(path) // #nosec G304 -- intentional test fixture reproducing a path-traversal vulnerability pattern for the taint analyzer to detect; not production code
}
