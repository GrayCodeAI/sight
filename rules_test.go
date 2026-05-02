package sight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadProjectRules_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	result := LoadProjectRules(dir)
	if result != "" {
		t.Errorf("expected empty string for dir with no rules, got %q", result)
	}
}

func TestLoadProjectRules_CLAUDEmd(t *testing.T) {
	dir := t.TempDir()
	content := "Always use error wrapping with fmt.Errorf."
	if err := os.WriteFile(filepath.Join(dir, "CLAUDE.md"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result := LoadProjectRules(dir)
	if !strings.Contains(result, "Claude Rules") {
		t.Error("expected 'Claude Rules' section header")
	}
	if !strings.Contains(result, content) {
		t.Error("expected CLAUDE.md content in output")
	}
	if !strings.Contains(result, "CLAUDE.md") {
		t.Error("expected relative path in output")
	}
}

func TestLoadProjectRules_CONTRIBUTINGmd(t *testing.T) {
	dir := t.TempDir()
	content := "Please follow the coding guidelines."
	if err := os.WriteFile(filepath.Join(dir, "CONTRIBUTING.md"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result := LoadProjectRules(dir)
	if !strings.Contains(result, "Contributing Guidelines") {
		t.Error("expected 'Contributing Guidelines' section header")
	}
	if !strings.Contains(result, content) {
		t.Error("expected CONTRIBUTING.md content in output")
	}
}

func TestLoadProjectRules_SightRules(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, ".sight", "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatal(err)
	}
	content := "No global variables allowed."
	if err := os.WriteFile(filepath.Join(rulesDir, "no-globals.md"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result := LoadProjectRules(dir)
	if !strings.Contains(result, "Sight Rules") {
		t.Error("expected 'Sight Rules' section header")
	}
	if !strings.Contains(result, content) {
		t.Error("expected rule content in output")
	}
}

func TestLoadProjectRules_CursorRules(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, ".cursor", "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatal(err)
	}
	content := "Use tabs for indentation."
	if err := os.WriteFile(filepath.Join(rulesDir, "style.md"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result := LoadProjectRules(dir)
	if !strings.Contains(result, "Cursor Rules") {
		t.Error("expected 'Cursor Rules' section header")
	}
	if !strings.Contains(result, content) {
		t.Error("expected cursor rule content in output")
	}
}

func TestLoadProjectRules_MultipleSources(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "CLAUDE.md"), []byte("Claude rule"), 0644)
	os.WriteFile(filepath.Join(dir, "CONTRIBUTING.md"), []byte("Contributing rule"), 0644)

	sightRulesDir := filepath.Join(dir, ".sight", "rules")
	os.MkdirAll(sightRulesDir, 0755)
	os.WriteFile(filepath.Join(sightRulesDir, "custom.md"), []byte("Custom rule"), 0644)

	result := LoadProjectRules(dir)
	if !strings.Contains(result, "Claude Rules") {
		t.Error("expected 'Claude Rules' section")
	}
	if !strings.Contains(result, "Contributing Guidelines") {
		t.Error("expected 'Contributing Guidelines' section")
	}
	if !strings.Contains(result, "Sight Rules") {
		t.Error("expected 'Sight Rules' section")
	}
}

func TestLoadProjectRules_EmptyFileSkipped(t *testing.T) {
	dir := t.TempDir()
	// Empty file (just whitespace)
	os.WriteFile(filepath.Join(dir, "CLAUDE.md"), []byte("   \n  \n"), 0644)

	result := LoadProjectRules(dir)
	if result != "" {
		t.Errorf("expected empty result for whitespace-only file, got %q", result)
	}
}

func TestGlobFiles_NoMatch(t *testing.T) {
	dir := t.TempDir()
	result := globFiles(filepath.Join(dir, "*.md"))
	if len(result) != 0 {
		t.Errorf("expected nil for no matches, got %v", result)
	}
}

func TestGlobFiles_WithMatches(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.md"), []byte("a"), 0644)
	os.WriteFile(filepath.Join(dir, "b.md"), []byte("b"), 0644)
	os.WriteFile(filepath.Join(dir, "c.txt"), []byte("c"), 0644)

	result := globFiles(filepath.Join(dir, "*.md"))
	if len(result) != 2 {
		t.Errorf("expected 2 matches, got %d", len(result))
	}
}

func TestFileIfExists_Exists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	os.WriteFile(path, []byte("content"), 0644)

	result := fileIfExists(path)
	if len(result) != 1 || result[0] != path {
		t.Errorf("expected [%s], got %v", path, result)
	}
}

func TestFileIfExists_NotExists(t *testing.T) {
	result := fileIfExists("/nonexistent/file.md")
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}
