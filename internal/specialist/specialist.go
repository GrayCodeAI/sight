// Package specialist provides the specialist framework for hawk-eco.
// Specialists are sub-agents with specific tool permissions and scopes.
package specialist

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Specialist represents a specialized review agent with specific permissions.
type Specialist struct {
	Name        string
	Description string
	Prompt      string
	Tools       []string
	Scope       string
}

// Scope constants define specialist scopes.
const (
	ScopeBuiltin = "builtin"
	ScopeUser    = "user"
	ScopeProject = "project"
)

// Permission constants define tool permissions.
const (
	PermissionReadOnly = "read-only"
	PermissionPlan     = "plan"
	PermissionDeny     = "deny"
	PermissionAllow    = "allow"
)

// SpecialistManifest represents a specialist's manifest file.
type SpecialistManifest struct {
	Description string   `yaml:"description"`
	Tools       []string `yaml:"tools"`
}

// NewSpecialist creates a new specialist.
func NewSpecialist(name, description, prompt string, tools []string, scope string) *Specialist {
	return &Specialist{
		Name:        name,
		Description: description,
		Prompt:      prompt,
		Tools:       tools,
		Scope:       scope,
	}
}

// HasTool checks if the specialist has a specific tool.
func (s *Specialist) HasTool(tool string) bool {
	for _, t := range s.Tools {
		if strings.EqualFold(t, tool) {
			return true
		}
	}
	return false
}

// Manager manages specialists across different scopes.
type Manager struct {
	mu          sync.RWMutex
	specialists map[string]*Specialist
}

// NewManager creates a new specialist manager.
func NewManager() *Manager {
	return &Manager{
		specialists: make(map[string]*Specialist),
	}
}

// Register adds a specialist to the manager.
func (m *Manager) Register(s *Specialist) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.specialists[s.Name] = s
}

// Get retrieves a specialist by name.
func (m *Manager) Get(name string) *Specialist {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.specialists[name]
}

// List returns all registered specialists.
func (m *Manager) List() []*Specialist {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Specialist, 0, len(m.specialists))
	for _, s := range m.specialists {
		result = append(result, s)
	}
	return result
}

// BuiltinSpecialists returns the default built-in specialists.
func BuiltinSpecialists() []*Specialist {
	return []*Specialist{
		{
			Name:        "security-reviewer",
			Description: "Reviews code for security vulnerabilities",
			Prompt:      "You are a security expert reviewing code for vulnerabilities.",
			Tools:       []string{"read-only", "plan"},
			Scope:       ScopeBuiltin,
		},
		{
			Name:        "style-reviewer",
			Description: "Reviews code for style and consistency",
			Prompt:      "You are a style expert reviewing code for consistency and best practices.",
			Tools:       []string{"plan"},
			Scope:       ScopeBuiltin,
		},
		{
			Name:        "correctness-reviewer",
			Description: "Reviews code for correctness issues",
			Prompt:      "You are a correctness expert reviewing code for logic errors and bugs.",
			Tools:       []string{"read-only", "plan"},
			Scope:       ScopeBuiltin,
		},
	}
}

// RegisterBuiltin registers all built-in specialists.
func (m *Manager) RegisterBuiltin() {
	for _, s := range BuiltinSpecialists() {
		m.Register(s)
	}
}

// LoadProjectSpecialists loads specialists from a project directory.
func (m *Manager) LoadProjectSpecialists(dir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Try multiple locations
	locations := []string{
		filepath.Join(dir, ".zero", "specialists"),
		filepath.Join(dir, "specialists"),
	}

	for _, loc := range locations {
		if err := m.loadSpecialistsFromDir(loc, ScopeProject); err == nil {
			return nil
		}
	}

	return nil
}

// LoadUserSpecialists loads specialists from user config directory.
func (m *Manager) LoadUserSpecialists(dir string) error {
	return m.loadSpecialistsFromDir(dir, ScopeUser)
}

// loadSpecialistsFromDir loads specialists from a directory.
func (m *Manager) loadSpecialistsFromDir(dir string, scope string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".md") && !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		manifestPath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(manifestPath) // #nosec G304 -- manifestPath is joined from a directory being scanned and an entry name returned by os.ReadDir on that same directory, not raw user input
		if err != nil {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		manifest := &SpecialistManifest{}

		if err := m.parseYAML(data, manifest); err != nil {
			continue
		}

		specialist := &Specialist{
			Name:        name,
			Description: manifest.Description,
			Scope:       scope,
		}

		m.specialists[name] = specialist
	}

	return nil
}

// parseYAML parses YAML content from a file.
func (m *Manager) parseYAML(data []byte, v interface{}) error {
	// Simple YAML parsing using strings
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if strings.HasPrefix(line, "description:") {
			desc := strings.TrimPrefix(line, "description:")
			if desc := strings.TrimSpace(desc); desc != "" && desc != "|" {
				switch {
				case strings.HasPrefix(desc, "\""):
					if strings.HasSuffix(desc, "\"") {
						i++
						continue
					}
				case strings.HasPrefix(desc, "|"):
					var content []string
					for j := i + 1; j < len(lines) && (strings.HasPrefix(strings.TrimSpace(lines[j]), " ") || strings.TrimSpace(lines[j]) == ""); j++ {
						content = append(content, strings.TrimSpace(lines[j]))
					}
					if len(content) > 0 {
						if desc := strings.Join(content, "\n"); desc != "" {
							break
						}
					}
				default:
					if desc != "" && desc != "|" {
						break
					}
				}
				break
			}
		}

		if strings.HasPrefix(line, "tools:") {
			var tools []string
			for j := i + 1; j < len(lines); j++ {
				toolLine := strings.TrimSpace(lines[j])
				if toolLine == "" || strings.HasPrefix(toolLine, " ") {
					if toolLine != "" {
						tools = append(tools, strings.TrimSpace(toolLine))
					}
				} else {
					break
				}
			}
			i += len(tools)
		}
	}

	return nil
}

// FindSpecialist finds a specialist by name with scope priority.
func (m *Manager) FindSpecialist(name string) *Specialist {
	return m.Get(name)
}

// ListByScope lists specialists filtered by scope.
func (m *Manager) ListByScope(scope string) []*Specialist {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Specialist
	for _, s := range m.specialists {
		if s.Scope == scope {
			result = append(result, s)
		}
	}
	return result
}

// Delete removes a specialist from the manager.
func (m *Manager) Delete(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.specialists, name)
}

// LoadAllSpecialists loads all specialists from default locations.
func (m *Manager) LoadAllSpecialists() error {
	// Register built-in specialists first
	m.RegisterBuiltin()

	// Load from user config
	userDir := filepath.Join(os.TempDir(), "hawk-eco", "specialists")
	if err := m.LoadUserSpecialists(userDir); err != nil {
		// Non-fatal: user specialists are optional
		fmt.Fprintf(os.Stderr, "warning: could not load user specialists: %v\n", err)
	}

	// Load from project directory
	if cwd, err := os.Getwd(); err == nil {
		if err := m.LoadProjectSpecialists(cwd); err != nil {
			// Non-fatal: project specialists are optional
			fmt.Fprintf(os.Stderr, "warning: could not load project specialists: %v\n", err)
		}
	}

	return nil
}
