package sight_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/GrayCodeAI/sight"
)

const goFixture = `package example

import "fmt"

// Config holds application configuration.
type Config struct {
	Host string
	Port int
}

// NewConfig creates a Config with defaults.
func NewConfig() *Config {
	return &Config{Host: "localhost", Port: 8080}
}

// Validate checks Config is well-formed.
func (c *Config) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("empty host")
	}
	return nil
}

const DefaultPort = 8080
var DefaultHost = "localhost"
`

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestSearchBySymbol_AllSymbols(t *testing.T) {
	path := writeTempFile(t, "example.go", goFixture)
	results, err := sight.SearchBySymbol(path, "", "")
	if err != nil {
		t.Fatalf("SearchBySymbol: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected symbols, got none")
	}
	kinds := map[string]bool{}
	for _, r := range results {
		kinds[r.Kind] = true
	}
	if !kinds["type"] {
		t.Error("expected at least one 'type' symbol")
	}
	if !kinds["function"] {
		t.Error("expected at least one 'function' symbol")
	}
}

func TestSearchBySymbol_ByName(t *testing.T) {
	path := writeTempFile(t, "example.go", goFixture)
	results, err := sight.SearchBySymbol(path, "Config", "")
	if err != nil {
		t.Fatalf("SearchBySymbol: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one Config symbol")
	}
	for _, r := range results {
		if r.Symbol == "" {
			t.Error("symbol name must not be empty")
		}
		if r.StartLine <= 0 {
			t.Error("start line must be > 0")
		}
	}
}

func TestSearchBySymbol_ByKind(t *testing.T) {
	path := writeTempFile(t, "example.go", goFixture)
	results, err := sight.SearchBySymbol(path, "", "function")
	if err != nil {
		t.Fatalf("SearchBySymbol: %v", err)
	}
	for _, r := range results {
		if r.Kind != "function" {
			t.Errorf("expected kind=function, got %q (symbol %q)", r.Kind, r.Symbol)
		}
	}
}

func TestGetSymbolBody(t *testing.T) {
	path := writeTempFile(t, "example.go", goFixture)
	result, err := sight.GetSymbolBody(path, "NewConfig")
	if err != nil {
		t.Fatalf("GetSymbolBody: %v", err)
	}
	if result.Body == "" {
		t.Error("body must not be empty")
	}
	if result.Symbol == "" {
		t.Error("symbol must not be empty")
	}
	if result.StartLine <= 0 {
		t.Errorf("StartLine = %d, want > 0", result.StartLine)
	}
}

func TestGetSymbolBody_NotFound(t *testing.T) {
	path := writeTempFile(t, "example.go", goFixture)
	_, err := sight.GetSymbolBody(path, "NonExistentFunction")
	if err == nil {
		t.Error("GetSymbolBody should return error for missing symbol")
	}
}

func TestSearchBySymbol_UnsupportedExt(t *testing.T) {
	path := writeTempFile(t, "data.xml", "<root/>")
	results, err := sight.SearchBySymbol(path, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for unsupported extension, got %d", len(results))
	}
}
