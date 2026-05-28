package sight

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FileConfig represents the contents of a .sight.toml configuration file.
type FileConfig struct {
	Model      string            `json:"model"`
	Concerns   []string          `json:"concerns"`
	FailOn     string            `json:"fail_on"`
	MaxTokens  int               `json:"max_tokens"`
	Exclude    []string          `json:"exclude"`
	GitContext *bool             `json:"git_context"`
	Reflection *bool             `json:"reflection"`
	Parallel   *bool             `json:"parallel"`
	Prompts    map[string]string `json:"prompts"`
}

// LoadConfigFile reads .sight.toml from the given directory (or parents).
// Returns nil if no config file is found. Errors only on malformed files.
func LoadConfigFile(dir string) (*FileConfig, error) {
	path := findConfigFile(dir)
	if path == "" {
		return nil, nil
	}

	const maxConfigSize = 1 << 20 // 1MB
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxConfigSize {
		return nil, fmt.Errorf("config file %s is too large (%d bytes, max %d bytes)", path, info.Size(), maxConfigSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parseTOMLConfig(string(data))
}

// ApplyFileConfig converts a FileConfig into Options.
func ApplyFileConfig(fc *FileConfig) []Option {
	if fc == nil {
		return nil
	}

	var opts []Option

	if fc.Model != "" {
		opts = append(opts, WithModel(fc.Model))
	}
	if len(fc.Concerns) > 0 {
		opts = append(opts, WithConcerns(fc.Concerns...))
	}
	if fc.FailOn != "" {
		opts = append(opts, WithFailOn(ParseSeverity(fc.FailOn)))
	}
	if fc.MaxTokens > 0 {
		opts = append(opts, WithMaxTokens(fc.MaxTokens))
	}
	if fc.GitContext != nil {
		opts = append(opts, WithGitContext(*fc.GitContext))
	}
	if fc.Reflection != nil {
		opts = append(opts, WithReflection(*fc.Reflection))
	}
	if fc.Parallel != nil {
		opts = append(opts, WithParallel(*fc.Parallel))
	}
	if len(fc.Exclude) > 0 {
		opts = append(opts, WithExclude(fc.Exclude...))
	}

	return opts
}

func findConfigFile(dir string) string {
	names := []string{".sight.toml", ".sight.json", "sight.toml"}

	for {
		for _, name := range names {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// parseTOMLConfig parses a simplified TOML format.
// Supports key = "value", key = true/false, key = 123, arrays, and [section] headers.
func parseTOMLConfig(content string) (*FileConfig, error) {
	cfg := &FileConfig{
		Prompts: make(map[string]string),
	}

	section := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}

		key, value, ok := parseTOMLKeyValue(line)
		if !ok {
			continue
		}

		if section == "prompts" {
			cfg.Prompts[key] = value
			continue
		}

		switch key {
		case "model":
			cfg.Model = value
		case "concerns":
			cfg.Concerns = parseTOMLArray(value)
		case "fail_on":
			cfg.FailOn = value
		case "max_tokens":
			if n := parseInt(value); n > 0 {
				cfg.MaxTokens = n
			}
		case "exclude":
			cfg.Exclude = parseTOMLArray(value)
		case "git_context":
			b := value == "true"
			cfg.GitContext = &b
		case "reflection":
			b := value == "true"
			cfg.Reflection = &b
		case "parallel":
			b := value == "true"
			cfg.Parallel = &b
		}
	}

	return cfg, nil
}

// parseTOMLKeyValue splits a TOML line into key and value, handling quoted values
// that may contain '=' signs.
func parseTOMLKeyValue(line string) (key, value string, ok bool) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	// Strip matching outer quotes
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
	}
	return key, value, key != ""
}

func parseTOMLArray(s string) []string {
	s = strings.Trim(s, "[]")
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"'`)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// parseInt parses a string as an integer with range validation.
// It reads leading digits (ignoring trailing non-digit chars for TOML compat)
// and caps the result at 1,000,000 to prevent unreasonable values.
func parseInt(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// Extract leading digits
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0
	}
	if n < 0 || n > 1_000_000 {
		return 0
	}
	return n
}
