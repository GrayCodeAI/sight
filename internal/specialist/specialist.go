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

// LoadProjectSpecialists loads specialists from every known project
// location that exists, merging their contents (later locations take
// precedence for a given name).
func (m *Manager) LoadProjectSpecialists(dir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	locations := []string{
		filepath.Join(dir, ".zero", "specialists"),
		filepath.Join(dir, "specialists"),
	}

	for _, loc := range locations {
		if err := m.loadSpecialistsFromDir(loc, ScopeProject); err != nil {
			return err
		}
	}

	return nil
}

// LoadUserSpecialists loads specialists from user config directory.
func (m *Manager) LoadUserSpecialists(dir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
			Tools:       manifest.Tools,
			Scope:       scope,
		}

		m.specialists[name] = specialist
	}

	return nil
}

// parseYAML does a minimal, dependency-free parse of the small subset of
// YAML used by specialist manifests: a top-level "description:" scalar
// (optionally a block scalar introduced by "|") and a top-level "tools:"
// sequence of "- item" entries indented under it.
func (m *Manager) parseYAML(data []byte, v interface{}) error {
	manifest, ok := v.(*SpecialistManifest)
	if !ok {
		return fmt.Errorf("parseYAML: unsupported target type %T", v)
	}

	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		switch {
		case strings.HasPrefix(line, "description:"):
			desc := strings.TrimSpace(strings.TrimPrefix(line, "description:"))
			desc = strings.Trim(desc, "\"")

			if desc == "|" || desc == ">" {
				var content []string
				j := i + 1
				for ; j < len(lines) && isIndented(lines[j]); j++ {
					content = append(content, strings.TrimSpace(lines[j]))
				}
				desc = strings.Join(content, "\n")
				i = j - 1
			}

			manifest.Description = desc

		case strings.HasPrefix(line, "tools:"):
			var tools []string
			j := i + 1
			for ; j < len(lines) && isIndented(lines[j]); j++ {
				item := strings.TrimPrefix(strings.TrimSpace(lines[j]), "- ")
				item = strings.TrimSpace(item)
				if item != "" {
					tools = append(tools, item)
				}
			}
			manifest.Tools = tools
			i = j - 1
		}
	}

	return nil
}

// isIndented reports whether line is a non-empty YAML line indented under
// its parent key (i.e. a continuation line, not the start of the next key).
func isIndented(line string) bool {
	if strings.TrimSpace(line) == "" {
		return false
	}
	return strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
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
