package sight

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseTOMLConfig_Basic(t *testing.T) {
	content := `
model = "gpt-4"
fail_on = "high"
max_tokens = 8192
git_context = true
reflection = false
parallel = true
concerns = ["security", "bugs"]
exclude = ["vendor/*", "*.min.js"]
`
	cfg, err := parseTOMLConfig(content)
	if err != nil {
		t.Fatalf("parseTOMLConfig error: %v", err)
	}
	if cfg.Model != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got %q", cfg.Model)
	}
	if cfg.FailOn != "high" {
		t.Errorf("expected fail_on 'high', got %q", cfg.FailOn)
	}
	if cfg.MaxTokens != 8192 {
		t.Errorf("expected max_tokens 8192, got %d", cfg.MaxTokens)
	}
	if cfg.GitContext == nil || !*cfg.GitContext {
		t.Error("expected git_context = true")
	}
	if cfg.Reflection == nil || *cfg.Reflection {
		t.Error("expected reflection = false")
	}
	if cfg.Parallel == nil || !*cfg.Parallel {
		t.Error("expected parallel = true")
	}
	if len(cfg.Concerns) != 2 {
		t.Fatalf("expected 2 concerns, got %d", len(cfg.Concerns))
	}
	if cfg.Concerns[0] != "security" || cfg.Concerns[1] != "bugs" {
		t.Errorf("unexpected concerns: %v", cfg.Concerns)
	}
	if len(cfg.Exclude) != 2 {
		t.Fatalf("expected 2 exclude patterns, got %d", len(cfg.Exclude))
	}
}

func TestParseTOMLConfig_WithSections(t *testing.T) {
	content := `
model = "claude-3"

[prompts]
system = "You are a strict reviewer"
review = "Check everything carefully"
`
	cfg, err := parseTOMLConfig(content)
	if err != nil {
		t.Fatalf("parseTOMLConfig error: %v", err)
	}
	if cfg.Model != "claude-3" {
		t.Errorf("expected model 'claude-3', got %q", cfg.Model)
	}
	if cfg.Prompts["system"] != "You are a strict reviewer" {
		t.Errorf("expected system prompt, got %q", cfg.Prompts["system"])
	}
	if cfg.Prompts["review"] != "Check everything carefully" {
		t.Errorf("expected review prompt, got %q", cfg.Prompts["review"])
	}
}

func TestParseTOMLConfig_Comments(t *testing.T) {
	content := `
# This is a comment
model = "gpt-4"
# Another comment
fail_on = "medium"
`
	cfg, err := parseTOMLConfig(content)
	if err != nil {
		t.Fatalf("parseTOMLConfig error: %v", err)
	}
	if cfg.Model != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got %q", cfg.Model)
	}
	if cfg.FailOn != "medium" {
		t.Errorf("expected fail_on 'medium', got %q", cfg.FailOn)
	}
}

func TestParseTOMLConfig_Empty(t *testing.T) {
	cfg, err := parseTOMLConfig("")
	if err != nil {
		t.Fatalf("parseTOMLConfig error: %v", err)
	}
	if cfg.Model != "" {
		t.Errorf("expected empty model, got %q", cfg.Model)
	}
	if cfg.MaxTokens != 0 {
		t.Errorf("expected 0 max_tokens, got %d", cfg.MaxTokens)
	}
}

func TestParseTOMLConfig_InvalidMaxTokens(t *testing.T) {
	content := `max_tokens = "not a number"`
	cfg, err := parseTOMLConfig(content)
	if err != nil {
		t.Fatalf("parseTOMLConfig error: %v", err)
	}
	// parseInt("not a number") returns 0, which is not > 0, so MaxTokens stays 0
	if cfg.MaxTokens != 0 {
		t.Errorf("expected 0 max_tokens for invalid input, got %d", cfg.MaxTokens)
	}
}

func TestParseTOMLConfig_BooleanFalse(t *testing.T) {
	content := `
git_context = false
reflection = false
parallel = false
`
	cfg, err := parseTOMLConfig(content)
	if err != nil {
		t.Fatalf("parseTOMLConfig error: %v", err)
	}
	if cfg.GitContext == nil || *cfg.GitContext {
		t.Error("expected git_context = false")
	}
	if cfg.Reflection == nil || *cfg.Reflection {
		t.Error("expected reflection = false")
	}
	if cfg.Parallel == nil || *cfg.Parallel {
		t.Error("expected parallel = false")
	}
}

func TestParseTOMLConfig_LineWithoutEquals(t *testing.T) {
	content := `
model = "gpt-4"
this line has no equals sign
fail_on = "low"
`
	cfg, err := parseTOMLConfig(content)
	if err != nil {
		t.Fatalf("parseTOMLConfig error: %v", err)
	}
	if cfg.Model != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got %q", cfg.Model)
	}
	if cfg.FailOn != "low" {
		t.Errorf("expected fail_on 'low', got %q", cfg.FailOn)
	}
}

func TestApplyFileConfig_Nil(t *testing.T) {
	opts := ApplyFileConfig(nil)
	if len(opts) != 0 {
		t.Errorf("expected 0 options for nil config, got %d", len(opts))
	}
}

func TestApplyFileConfig_Full(t *testing.T) {
	tr := true
	fc := &FileConfig{
		Model:      "gpt-4",
		Concerns:   []string{"security"},
		FailOn:     "high",
		MaxTokens:  4096,
		Exclude:    []string{"vendor/*"},
		GitContext: &tr,
		Reflection: &tr,
		Parallel:   &tr,
	}
	opts := ApplyFileConfig(fc)
	// Should produce 8 options (one for each non-zero field)
	if len(opts) != 8 {
		t.Errorf("expected 8 options, got %d", len(opts))
	}
}

func TestApplyFileConfig_Partial(t *testing.T) {
	fc := &FileConfig{
		Model: "gpt-4",
	}
	opts := ApplyFileConfig(fc)
	if len(opts) != 1 {
		t.Errorf("expected 1 option, got %d", len(opts))
	}
}

func TestApplyFileConfig_Empty(t *testing.T) {
	fc := &FileConfig{}
	opts := ApplyFileConfig(fc)
	if len(opts) != 0 {
		t.Errorf("expected 0 options for empty config, got %d", len(opts))
	}
}

func TestFindConfigFile_Found(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".sight.toml")
	if err := os.WriteFile(configPath, []byte("model = \"gpt-4\""), 0644); err != nil {
		t.Fatal(err)
	}

	found := findConfigFile(dir)
	if found != configPath {
		t.Errorf("expected %s, got %s", configPath, found)
	}
}

func TestFindConfigFile_ParentDir(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "sub", "dir")
	if err := os.MkdirAll(child, 0755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(parent, ".sight.toml")
	if err := os.WriteFile(configPath, []byte("model = \"gpt-4\""), 0644); err != nil {
		t.Fatal(err)
	}

	found := findConfigFile(child)
	if found != configPath {
		t.Errorf("expected %s, got %s", configPath, found)
	}
}

func TestFindConfigFile_AlternateNames(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sight.toml")
	if err := os.WriteFile(configPath, []byte("model = \"gpt-4\""), 0644); err != nil {
		t.Fatal(err)
	}

	found := findConfigFile(dir)
	if found != configPath {
		t.Errorf("expected %s, got %s", configPath, found)
	}
}

func TestFindConfigFile_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".sight.json")
	if err := os.WriteFile(configPath, []byte(`{"model": "gpt-4"}`), 0644); err != nil {
		t.Fatal(err)
	}

	found := findConfigFile(dir)
	if found != configPath {
		t.Errorf("expected %s, got %s", configPath, found)
	}
}

func TestFindConfigFile_NotFound(t *testing.T) {
	dir := t.TempDir()
	found := findConfigFile(dir)
	if found != "" {
		t.Errorf("expected empty string, got %s", found)
	}
}

func TestFindConfigFile_PrioritizesToml(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".sight.toml"), []byte("model = \"a\""), 0644)
	os.WriteFile(filepath.Join(dir, ".sight.json"), []byte(`{"model": "b"}`), 0644)

	found := findConfigFile(dir)
	expected := filepath.Join(dir, ".sight.toml")
	if found != expected {
		t.Errorf("expected .sight.toml to have priority, got %s", found)
	}
}

func TestLoadConfigFile_NoFile(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadConfigFile(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Error("expected nil config when no file found")
	}
}

func TestLoadConfigFile_ValidFile(t *testing.T) {
	dir := t.TempDir()
	content := `
model = "gpt-4"
fail_on = "high"
max_tokens = 4096
`
	if err := os.WriteFile(filepath.Join(dir, ".sight.toml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfigFile(dir)
	if err != nil {
		t.Fatalf("LoadConfigFile error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Model != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got %q", cfg.Model)
	}
}

func TestParseTOMLArray(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{`["a", "b", "c"]`, []string{"a", "b", "c"}},
		{`[a, b]`, []string{"a", "b"}},
		{`["single"]`, []string{"single"}},
		{`[]`, nil},
	}

	for _, tc := range tests {
		result := parseTOMLArray(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("parseTOMLArray(%q): expected %d items, got %d", tc.input, len(tc.expected), len(result))
			continue
		}
		for i := range result {
			if result[i] != tc.expected[i] {
				t.Errorf("parseTOMLArray(%q)[%d]: expected %q, got %q", tc.input, i, tc.expected[i], result[i])
			}
		}
	}
}

func TestParseInt(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"123", 123},
		{"0", 0},
		{"4096", 4096},
		{"abc", 0},
		{"12abc", 12},
		{"", 0},
	}

	for _, tc := range tests {
		result := parseInt(tc.input)
		if result != tc.expected {
			t.Errorf("parseInt(%q): expected %d, got %d", tc.input, tc.expected, result)
		}
	}
}
