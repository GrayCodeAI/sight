package sight

import (
	"os"
	"path/filepath"
	"strings"
)

// FileConfig represents the contents of a .sight.toml configuration file.
type FileConfig struct {
	Model       string            `json:"model"`
	Concerns    []string          `json:"concerns"`
	FailOn      string            `json:"fail_on"`
	MaxTokens   int               `json:"max_tokens"`
	Exclude     []string          `json:"exclude"`
	GitContext  *bool             `json:"git_context"`
	Reflection  *bool             `json:"reflection"`
	Parallel    *bool             `json:"parallel"`
	Prompts     map[string]string `json:"prompts"`
}

// LoadConfigFile reads .sight.toml from the given directory (or parents).
// Returns nil if no config file is found. Errors only on malformed files.
func LoadConfigFile(dir string) (*FileConfig, error) {
	path := findConfigFile(dir)
	if path == "" {
		return nil, nil
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
// Supports key = "value", key = true/false, key = 123, and [section] headers.
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

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"'`)

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

func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n
}
