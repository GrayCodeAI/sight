package context

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitRepo creates a throwaway git repo in a temp dir, chdirs into it for the
// duration of the test, and returns a commit helper. It skips the test if git
// is unavailable. chdir is process-global, so these tests must not run in
// parallel (they don't call t.Parallel).
func gitRepo(t *testing.T) func(msg string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()

	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		// Keep config local + deterministic regardless of the host's git config.
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Tester", "GIT_AUTHOR_EMAIL=tester@example.com",
			"GIT_COMMITTER_NAME=Tester", "GIT_COMMITTER_EMAIL=tester@example.com",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	run("init", "-q")
	run("config", "user.name", "Tester")
	run("config", "user.email", "tester@example.com")
	run("checkout", "-q", "-b", "main")

	commit := func(msg string) {
		t.Helper()
		run("add", "-A")
		run("commit", "-q", "--allow-empty", "-m", msg)
	}
	return commit
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(".", name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestChangedFiles(t *testing.T) {
	commit := gitRepo(t)
	writeFile(t, "a.txt", "one\n")
	commit("base commit")
	// Tag the base, then add a new file on top.
	writeFile(t, "b.txt", "two\n")
	commit("add b.txt")

	files, err := ChangedFiles("HEAD~1")
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	found := false
	for _, f := range files {
		if f == "b.txt" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected b.txt in changed files, got %v", files)
	}
}

func TestChangedFiles_NoChanges(t *testing.T) {
	commit := gitRepo(t)
	writeFile(t, "a.txt", "one\n")
	commit("only commit")

	// HEAD...HEAD has no changes -> nil slice, no error.
	files, err := ChangedFiles("HEAD")
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected no changed files, got %v", files)
	}
}

func TestDiffBase(t *testing.T) {
	commit := gitRepo(t)
	writeFile(t, "a.txt", "one\n")
	commit("base")
	writeFile(t, "a.txt", "one\ntwo\n")
	commit("change a.txt")

	diff, err := DiffBase("HEAD~1")
	if err != nil {
		t.Fatalf("DiffBase: %v", err)
	}
	if !strings.Contains(diff, "a.txt") {
		t.Errorf("expected diff to mention a.txt, got:\n%s", diff)
	}
	if !strings.Contains(diff, "+two") {
		t.Errorf("expected diff to contain the added line '+two', got:\n%s", diff)
	}
}

func TestBlame(t *testing.T) {
	commit := gitRepo(t)
	writeFile(t, "a.txt", "line one\nline two\nline three\n")
	commit("add a.txt")

	out, err := Blame("a.txt", 1, 3)
	if err != nil {
		t.Fatalf("Blame: %v", err)
	}
	// parseBlameAuthors yields "Author(count)" — our committer is "Tester".
	if !strings.Contains(out, "Tester") {
		t.Errorf("expected blame summary to credit Tester, got %q", out)
	}
}

func TestBlame_InvalidPath(t *testing.T) {
	gitRepo(t)
	if _, err := Blame("../escape.txt", 1, 1); err == nil {
		t.Error("expected error for path traversing outside working dir")
	}
}

func TestEnrich_RecentCommits(t *testing.T) {
	commit := gitRepo(t)
	writeFile(t, "a.txt", "v1\n")
	commit("first change to a.txt")
	writeFile(t, "a.txt", "v2\n")
	commit("second change to a.txt")

	ctxs := Enrich([]string{"a.txt"})
	if len(ctxs) != 1 {
		t.Fatalf("expected 1 context, got %d", len(ctxs))
	}
	if ctxs[0].Path != "a.txt" {
		t.Errorf("path = %q, want a.txt", ctxs[0].Path)
	}
	if len(ctxs[0].RecentCommits) == 0 {
		t.Errorf("expected recent commits for a.txt, got none")
	}
}
