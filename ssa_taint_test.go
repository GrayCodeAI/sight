package sight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureEnv returns the process environment with workspace mode disabled so
// the nested testdata module is treated as its own main module.
func fixtureEnv() []string {
	return append(os.Environ(), "GOWORK=off")
}

func TestSSATaint_CrossFunctionFlows(t *testing.T) {
	dir, err := filepath.Abs("testdata/crossfunc")
	if err != nil {
		t.Fatal(err)
	}
	a := NewSSATaintAnalyzer()
	a.Env = fixtureEnv()
	findings, err := a.AnalyzePackages(dir, ".")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected cross-function taint findings, got none")
	}

	kinds := map[string]int{}
	for _, f := range findings {
		if f.Concern != "taint:ssa-data-flow" {
			t.Errorf("unexpected concern %q", f.Concern)
		}
		for _, want := range []string{"SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL"} {
			if strings.Contains(f.Message, want) {
				kinds[want]++
			}
		}
	}

	// Source in handler() reaches sinks in runQuery/runCmd/readConfig — flows
	// the function-scoped regex analyzer cannot see.
	for _, want := range []string{"SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL"} {
		if kinds[want] == 0 {
			t.Errorf("expected a %s finding from cross-function flow; findings=%v", want, summarize(findings))
		}
	}

	// The filepath.Clean-sanitized os.ReadFile must NOT be flagged: exactly one
	// path-traversal finding (readConfig), not two.
	if kinds["PATH_TRAVERSAL"] != 1 {
		t.Errorf("sanitizer suppression failed: expected exactly 1 PATH_TRAVERSAL finding, got %d", kinds["PATH_TRAVERSAL"])
	}
}

func TestSSATaint_CleanPackageNoFindings(t *testing.T) {
	dir, err := filepath.Abs("testdata/clean")
	if err != nil {
		t.Fatal(err)
	}
	a := NewSSATaintAnalyzer()
	a.Env = fixtureEnv()
	findings, err := a.AnalyzePackages(dir, ".")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings in clean package, got %v", summarize(findings))
	}
}

func summarize(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Message)
	}
	return out
}
