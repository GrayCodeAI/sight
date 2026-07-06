// Package hook provides hook system for hawk-eco.
// Hooks allow custom commands to run at specific lifecycle points.
package hook

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// HookType represents the type of hook.
type HookType string

const (
	HookBeforeReview HookType = "beforeReview"
	HookAfterReview  HookType = "afterReview"
	HookSessionStart  HookType = "sessionStart"
	HookSessionEnd    HookType = "sessionEnd"
)

// Hook represents a lifecycle hook.
type Hook struct {
	Name    string
	Command string
	Args    []string
}

// Dispatcher manages hooks and dispatches them.
type Dispatcher struct {
	mu      sync.RWMutex
	hooks   map[HookType][]*Hook
}

// NewDispatcher creates a new hook dispatcher.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		hooks: make(map[HookType][]*Hook),
	}
}

// Register adds a hook for a specific type.
func (d *Dispatcher) Register(hookType HookType, hook *Hook) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.hooks[hookType] == nil {
		d.hooks[hookType] = []*Hook{}
	}
	d.hooks[hookType] = append(d.hooks[hookType], hook)
}

// DispatchBeforeReview runs hooks before a review.
func (d *Dispatcher) DispatchBeforeReview(context string) error {
	return d.dispatch(HookBeforeReview, context)
}

// DispatchAfterReview runs hooks after a review.
func (d *Dispatcher) DispatchAfterReview(result string) error {
	return d.dispatch(HookAfterReview, result)
}

// dispatch runs all hooks of a specific type.
func (d *Dispatcher) dispatch(hookType HookType, context string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	hooks, ok := d.hooks[hookType]
	if !ok {
		return nil
	}

	for _, hook := range hooks {
		cmd := exec.Command(hook.Command, hook.Args...)
		cmd.Env = append(os.Environ(), fmt.Sprintf("HOOK_CONTEXT=%s", context))

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("hook %s failed: %w, output: %s", hook.Name, err, string(output))
		}

		fmt.Printf("Hook %s executed successfully\n", hook.Name)
	}

	return nil
}

// List returns all registered hooks.
func (d *Dispatcher) List() map[HookType][]*Hook {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.hooks
}

// RegisterBuiltin registers default hooks.
func (d *Dispatcher) RegisterBuiltin() {
	// Built-in hooks can be registered here
	// Example: post-review lint check
	d.Register(HookAfterReview, &Hook{
		Name:    "post-review-check",
		Command: "lint",
		Args:    []string{"--check"},
	})
}

// LoadHooksFromDir loads hooks from a directory.
func (d *Dispatcher) LoadHooksFromDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".md") && !strings.HasSuffix(entry.Name(), ".json") && !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		hookPath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(hookPath)
		if err != nil {
			continue
		}

		// Simple hook registration - hook name is the file stem
		name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		command := d.extractCommand(data)

		if command != "" {
			d.Register(HookBeforeReview, &Hook{
				Name:    name,
				Command: command,
			})
		}
	}

	return nil
}

// extractCommand extracts the command from hook content.
func (d *Dispatcher) extractCommand(data []byte) string {
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "command:") {
			cmd := strings.TrimPrefix(line, "command:")
			cmd = strings.TrimSpace(cmd)
			return cmd
		}
	}
	return ""
}

// parseHookContent parses hook content from a file.
func (d *Dispatcher) parseHookContent(data []byte) *Hook {
	// Simple parsing: extract command and args
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "command:") {
			cmd := strings.TrimPrefix(line, "command:")
			cmd = strings.TrimSpace(cmd)
			cmd = strings.Trim(cmd, "\"'")

			var args []string
			if i+1 < len(lines) {
				for j := i + 1; j < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[j]), "-") || strings.TrimSpace(lines[j]) == ""; j++ {
					arg := strings.TrimSpace(lines[j])
					if arg != "" {
						arg = strings.Trim(arg, "\"'")
						args = append(args, arg)
					}
				}
			}

			return &Hook{
				Command: cmd,
				Args:    args,
			}
		}
	}

	return nil
}

// HookTypeFromString converts a string to HookType.
func HookTypeFromString(s string) HookType {
	switch strings.ToLower(s) {
	case "beforereview":
		return HookBeforeReview
	case "afterreview":
		return HookAfterReview
	case "sessionstart":
		return HookSessionStart
	case "sessionend":
		return HookSessionEnd
	default:
		return HookType(s)
	}
}
