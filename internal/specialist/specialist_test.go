package specialist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewSpecialist(t *testing.T) {
	s := NewSpecialist("reviewer", "desc", "prompt text", []string{"read-only"}, ScopeBuiltin)
	if s.Name != "reviewer" || s.Description != "desc" || s.Prompt != "prompt text" {
		t.Fatalf("unexpected specialist: %+v", s)
	}
	if len(s.Tools) != 1 || s.Tools[0] != "read-only" {
		t.Fatalf("unexpected tools: %+v", s.Tools)
	}
	if s.Scope != ScopeBuiltin {
		t.Fatalf("scope = %q, want %q", s.Scope, ScopeBuiltin)
	}
}

func TestSpecialistHasTool(t *testing.T) {
	s := NewSpecialist("s", "d", "p", []string{"Read-Only", "plan"}, ScopeUser)

	if !s.HasTool("read-only") {
		t.Fatal("HasTool should be case-insensitive and match \"read-only\"")
	}
	if !s.HasTool("PLAN") {
		t.Fatal("HasTool should match \"plan\" case-insensitively")
	}
	if s.HasTool("deny") {
		t.Fatal("HasTool should not match an absent tool")
	}
}

func TestManagerRegisterGetList(t *testing.T) {
	m := NewManager()

	if got := m.Get("missing"); got != nil {
		t.Fatalf("Get on empty manager = %+v, want nil", got)
	}
	if got := m.List(); len(got) != 0 {
		t.Fatalf("List on empty manager = %+v, want empty", got)
	}

	s1 := NewSpecialist("one", "d1", "p1", nil, ScopeBuiltin)
	s2 := NewSpecialist("two", "d2", "p2", nil, ScopeUser)
	m.Register(s1)
	m.Register(s2)

	if got := m.Get("one"); got != s1 {
		t.Fatalf("Get(\"one\") = %+v, want %+v", got, s1)
	}

	list := m.List()
	if len(list) != 2 {
		t.Fatalf("List() len = %d, want 2", len(list))
	}
}

func TestManagerDelete(t *testing.T) {
	m := NewManager()
	m.Register(NewSpecialist("one", "d", "p", nil, ScopeBuiltin))

	m.Delete("one")
	if got := m.Get("one"); got != nil {
		t.Fatalf("Get after Delete = %+v, want nil", got)
	}

	// Deleting an absent entry must not panic.
	m.Delete("absent")
}

func TestBuiltinSpecialists(t *testing.T) {
	specialists := BuiltinSpecialists()
	if len(specialists) == 0 {
		t.Fatal("BuiltinSpecialists returned none")
	}

	names := map[string]bool{}
	for _, s := range specialists {
		if s.Scope != ScopeBuiltin {
			t.Fatalf("specialist %q has scope %q, want %q", s.Name, s.Scope, ScopeBuiltin)
		}
		if s.Name == "" || s.Prompt == "" {
			t.Fatalf("specialist has empty Name/Prompt: %+v", s)
		}
		names[s.Name] = true
	}
	for _, want := range []string{"security-reviewer", "style-reviewer", "correctness-reviewer"} {
		if !names[want] {
			t.Fatalf("BuiltinSpecialists missing %q", want)
		}
	}
}

func TestManagerRegisterBuiltin(t *testing.T) {
	m := NewManager()
	m.RegisterBuiltin()

	for _, s := range BuiltinSpecialists() {
		if got := m.Get(s.Name); got == nil {
			t.Fatalf("RegisterBuiltin did not register %q", s.Name)
		}
	}
}

func TestManagerFindSpecialist(t *testing.T) {
	m := NewManager()
	s := NewSpecialist("one", "d", "p", nil, ScopeBuiltin)
	m.Register(s)

	if got := m.FindSpecialist("one"); got != s {
		t.Fatalf("FindSpecialist(\"one\") = %+v, want %+v", got, s)
	}
	if got := m.FindSpecialist("absent"); got != nil {
		t.Fatalf("FindSpecialist(\"absent\") = %+v, want nil", got)
	}
}

func TestManagerListByScope(t *testing.T) {
	m := NewManager()
	m.Register(NewSpecialist("b1", "d", "p", nil, ScopeBuiltin))
	m.Register(NewSpecialist("b2", "d", "p", nil, ScopeBuiltin))
	m.Register(NewSpecialist("u1", "d", "p", nil, ScopeUser))

	builtin := m.ListByScope(ScopeBuiltin)
	if len(builtin) != 2 {
		t.Fatalf("ListByScope(builtin) len = %d, want 2", len(builtin))
	}
	user := m.ListByScope(ScopeUser)
	if len(user) != 1 {
		t.Fatalf("ListByScope(user) len = %d, want 1", len(user))
	}
	if got := m.ListByScope(ScopeProject); len(got) != 0 {
		t.Fatalf("ListByScope(project) len = %d, want 0", len(got))
	}
}

func TestLoadSpecialistsFromDirNonexistent(t *testing.T) {
	m := NewManager()
	err := m.loadSpecialistsFromDir(filepath.Join(t.TempDir(), "does-not-exist"), ScopeUser)
	if err != nil {
		t.Fatalf("loadSpecialistsFromDir on missing dir returned err: %v", err)
	}
	if len(m.List()) != 0 {
		t.Fatal("loadSpecialistsFromDir on missing dir should register nothing")
	}
}

func TestLoadSpecialistsFromDirParsesManifests(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "reviewer.md"), "description: Reviews things\ntools:\n  read-only\n  plan\n")
	writeFile(t, filepath.Join(dir, "notes.txt"), "not a manifest, must be ignored")
	writeFile(t, filepath.Join(dir, "empty.yaml"), "")

	m := NewManager()
	if err := m.loadSpecialistsFromDir(dir, ScopeProject); err != nil {
		t.Fatalf("loadSpecialistsFromDir returned err: %v", err)
	}

	got := m.Get("reviewer")
	if got == nil {
		t.Fatal("expected \"reviewer\" specialist to be registered")
	}
	if got.Scope != ScopeProject {
		t.Fatalf("scope = %q, want %q", got.Scope, ScopeProject)
	}
	if got.Description != "Reviews things" {
		t.Fatalf("description = %q, want %q", got.Description, "Reviews things")
	}

	if m.Get("notes") != nil {
		t.Fatal("non .md/.yaml/.yml file should not be registered")
	}
	if got := m.Get("empty"); got == nil {
		t.Fatal("expected \"empty\" manifest to still register a specialist with empty fields")
	}
}

func TestLoadProjectSpecialists(t *testing.T) {
	dir := t.TempDir()
	specDir := filepath.Join(dir, "specialists")
	if err := os.MkdirAll(specDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeFile(t, filepath.Join(specDir, "custom.md"), "description: Custom reviewer\n")

	m := NewManager()
	if err := m.LoadProjectSpecialists(dir); err != nil {
		t.Fatalf("LoadProjectSpecialists returned err: %v", err)
	}
	if got := m.Get("custom"); got == nil {
		t.Fatal("LoadProjectSpecialists did not load from ./specialists")
	}
}

func TestLoadProjectSpecialistsNoLocations(t *testing.T) {
	m := NewManager()
	if err := m.LoadProjectSpecialists(t.TempDir()); err != nil {
		t.Fatalf("LoadProjectSpecialists with no specialist dirs returned err: %v", err)
	}
}

func TestLoadUserSpecialists(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "user.yaml"), "description: User specialist\n")

	m := NewManager()
	if err := m.LoadUserSpecialists(dir); err != nil {
		t.Fatalf("LoadUserSpecialists returned err: %v", err)
	}
	if got := m.Get("user"); got == nil {
		t.Fatal("LoadUserSpecialists did not register \"user\"")
	}
}

func TestLoadAllSpecialists(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restoring Chdir: %v", err)
		}
	})

	m := NewManager()
	if err := m.LoadAllSpecialists(); err != nil {
		t.Fatalf("LoadAllSpecialists returned err: %v", err)
	}

	for _, s := range BuiltinSpecialists() {
		if got := m.Get(s.Name); got == nil {
			t.Fatalf("LoadAllSpecialists did not register builtin %q", s.Name)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}
