package hook

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewDispatcher(t *testing.T) {
	d := NewDispatcher()

	if d == nil {
		t.Fatal("expected non-nil dispatcher")
	}

	if len(d.List()) != 0 {
		t.Errorf("expected 0 hooks, got %d", len(d.List()))
	}
}

func TestRegisterHook(t *testing.T) {
	d := NewDispatcher()

	hook := &Hook{
		Name:    "test-hook",
		Command: "echo",
		Args:    []string{"hello"},
	}

	d.Register(HookBeforeReview, hook)

	hooks := d.List()
	if hooks[HookBeforeReview] == nil {
		t.Fatal("expected beforeReview hooks")
	}

	if len(hooks[HookBeforeReview]) != 1 {
		t.Errorf("expected 1 hook, got %d", len(hooks[HookBeforeReview]))
	}

	if hooks[HookBeforeReview][0].Name != "test-hook" {
		t.Errorf("expected hook name 'test-hook', got %s", hooks[HookBeforeReview][0].Name)
	}
}

func TestRegisterMultipleHooks(t *testing.T) {
	d := NewDispatcher()

	hook1 := &Hook{Name: "hook-1", Command: "echo"}
	hook2 := &Hook{Name: "hook-2", Command: "echo"}

	d.Register(HookBeforeReview, hook1)
	d.Register(HookBeforeReview, hook2)

	hooks := d.List()[HookBeforeReview]
	if len(hooks) != 2 {
		t.Errorf("expected 2 hooks, got %d", len(hooks))
	}
}

func TestDispatchNoHooks(t *testing.T) {
	d := NewDispatcher()

	err := d.DispatchBeforeReview("test context")
	if err != nil {
		t.Errorf("expected no error when no hooks, got %v", err)
	}
}

func TestHookTypeFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected HookType
	}{
		{"beforeReview", HookBeforeReview},
		{"afterReview", HookAfterReview},
		{"sessionStart", HookSessionStart},
		{"sessionEnd", HookSessionEnd},
		{"unknown", HookType("unknown")},
	}

	for _, tt := range tests {
		got := HookTypeFromString(tt.input)
		if got != tt.expected {
			t.Errorf("HookTypeFromString(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestRegisterBuiltin(t *testing.T) {
	d := NewDispatcher()
	d.RegisterBuiltin()

	hooks := d.List()
	// AfterRegisterBuiltin should have at least the post-review hook
	if len(hooks) == 0 {
		t.Error("expected at least one builtin hook")
	}
}

func TestLoadHooksFromDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a hook file with command
	hookContent := []byte(`---
command: echo
`)
	err := os.WriteFile(filepath.Join(tmpDir, "test.md"), hookContent, 0o644)
	if err != nil {
		t.Fatalf("failed to create hook file: %v", err)
	}

	d := NewDispatcher()
	err = d.LoadHooksFromDir(tmpDir)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	hooks := d.List()
	if len(hooks) == 0 {
		t.Error("expected to load hooks from directory")
	}
}
