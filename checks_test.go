package sight

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadChecks_NoDirectory(t *testing.T) {
	checks, err := LoadChecks("/nonexistent/path/to/checks")
	if err != nil {
		t.Fatalf("expected nil error for missing dir, got %v", err)
	}
	if len(checks) != 0 {
		t.Errorf("expected 0 checks, got %d", len(checks))
	}
}

func TestLoadChecks_BasicFile(t *testing.T) {
	dir := t.TempDir()
	content := `---
severity: high
languages: go, py
enabled: true
---
Do not use console.log or fmt.Println for debugging.
Remove all debug logging before merge.
`
	if err := os.WriteFile(filepath.Join(dir, "no-debug-logging.md"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	checks, err := LoadChecks(dir)
	if err != nil {
		t.Fatalf("LoadChecks failed: %v", err)
	}
	if len(checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(checks))
	}

	c := checks[0]
	if c.Name != "no-debug-logging" {
		t.Errorf("expected name 'no-debug-logging', got %q", c.Name)
	}
	if c.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", c.Severity)
	}
	if len(c.Languages) != 2 {
		t.Fatalf("expected 2 languages, got %d", len(c.Languages))
	}
	if c.Languages[0] != "go" || c.Languages[1] != "py" {
		t.Errorf("expected [go, py], got %v", c.Languages)
	}
	if !c.Enabled {
		t.Error("expected enabled=true")
	}
	if c.Prompt == "" {
		t.Error("expected non-empty prompt")
	}
}

func TestLoadChecks_NoFrontmatter(t *testing.T) {
	dir := t.TempDir()
	content := "Check that all errors are wrapped with context before returning."
	if err := os.WriteFile(filepath.Join(dir, "wrap-errors.md"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	checks, err := LoadChecks(dir)
	if err != nil {
		t.Fatalf("LoadChecks failed: %v", err)
	}
	if len(checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(checks))
	}

	c := checks[0]
	if c.Name != "wrap-errors" {
		t.Errorf("expected name 'wrap-errors', got %q", c.Name)
	}
	if c.Severity != "medium" {
		t.Errorf("expected default severity 'medium', got %q", c.Severity)
	}
	if !c.Enabled {
		t.Error("expected enabled=true by default")
	}
	if c.Prompt != content {
		t.Errorf("expected prompt to match content")
	}
}

func TestLoadChecks_DisabledCheck(t *testing.T) {
	dir := t.TempDir()
	content := `---
enabled: false
---
This check is disabled.
`
	if err := os.WriteFile(filepath.Join(dir, "disabled-check.md"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	checks, err := LoadChecks(dir)
	if err != nil {
		t.Fatalf("LoadChecks failed: %v", err)
	}
	if len(checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(checks))
	}
	if checks[0].Enabled {
		t.Error("expected enabled=false")
	}
}

func TestLoadChecks_SkipsNonMarkdown(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "check.md"), []byte("valid check"), 0644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a check"), 0644)
	os.WriteFile(filepath.Join(dir, "data.json"), []byte("{}"), 0644)

	checks, err := LoadChecks(dir)
	if err != nil {
		t.Fatalf("LoadChecks failed: %v", err)
	}
	if len(checks) != 1 {
		t.Errorf("expected 1 check (only .md), got %d", len(checks))
	}
}

func TestCustomChecksToConcerns_FiltersDisabled(t *testing.T) {
	checks := []CustomCheck{
		{Name: "active", Prompt: "check this", Enabled: true, Severity: "high"},
		{Name: "inactive", Prompt: "skip this", Enabled: false},
	}

	concerns := CustomChecksToConcerns(checks)
	if len(concerns) != 1 {
		t.Fatalf("expected 1 concern, got %d", len(concerns))
	}
	if concerns[0].Name != "custom:active" {
		t.Errorf("expected 'custom:active', got %q", concerns[0].Name)
	}
}

func TestLoadChecksFromRepo(t *testing.T) {
	dir := t.TempDir()
	checksDir := filepath.Join(dir, ".sight", "checks")
	if err := os.MkdirAll(checksDir, 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(checksDir, "test.md"), []byte("test check"), 0644)

	checks, err := LoadChecksFromRepo(dir)
	if err != nil {
		t.Fatalf("LoadChecksFromRepo failed: %v", err)
	}
	if len(checks) != 1 {
		t.Errorf("expected 1 check, got %d", len(checks))
	}
}
