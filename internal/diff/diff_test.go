package diff

import (
	"testing"
)

const sampleDiff = `diff --git a/main.go b/main.go
index abc1234..def5678 100644
--- a/main.go
+++ b/main.go
@@ -10,6 +10,8 @@ func main() {
 	fmt.Println("hello")
 	// existing code
 	doSomething()
+	// new feature
+	doNewThing()
 	cleanup()
 }

@@ -25,4 +27,7 @@ func doSomething() {
 	result := compute()
-	return result
+	if result == nil {
+		return defaultValue()
+	}
+	return result
 }
`

func TestParse_Basic(t *testing.T) {
	files := Parse(sampleDiff)

	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}

	f := files[0]
	if f.Path != "main.go" {
		t.Errorf("expected path main.go, got %s", f.Path)
	}
	if f.Added || f.Deleted || f.Renamed {
		t.Error("file should not be marked as added/deleted/renamed")
	}
	if len(f.Hunks) != 2 {
		t.Fatalf("expected 2 hunks, got %d", len(f.Hunks))
	}

	h1 := f.Hunks[0]
	if h1.OldStart != 10 || h1.NewStart != 10 {
		t.Errorf("hunk 1 start: old=%d new=%d", h1.OldStart, h1.NewStart)
	}

	addedLines := 0
	for _, l := range h1.Lines {
		if l.Type == LineAdded {
			addedLines++
		}
	}
	if addedLines != 2 {
		t.Errorf("expected 2 added lines in hunk 1, got %d", addedLines)
	}
}

func TestParse_NewFile(t *testing.T) {
	diff := `diff --git a/new.go b/new.go
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/new.go
@@ -0,0 +1,5 @@
+package main
+
+func newFunc() {
+	return
+}
`
	files := Parse(diff)
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if !files[0].Added {
		t.Error("file should be marked as added")
	}
	if files[0].Path != "new.go" {
		t.Errorf("expected path new.go, got %s", files[0].Path)
	}
}

func TestParse_DeletedFile(t *testing.T) {
	diff := `diff --git a/old.go b/old.go
deleted file mode 100644
index abc1234..0000000
--- a/old.go
+++ /dev/null
@@ -1,3 +0,0 @@
-package main
-
-func oldFunc() {}
`
	files := Parse(diff)
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if !files[0].Deleted {
		t.Error("file should be marked as deleted")
	}
}

func TestParse_Rename(t *testing.T) {
	diff := `diff --git a/old_name.go b/new_name.go
similarity index 95%
rename from old_name.go
rename to new_name.go
index abc1234..def5678 100644
--- a/old_name.go
+++ b/new_name.go
@@ -1,3 +1,3 @@
 package main

-func oldName() {}
+func newName() {}
`
	files := Parse(diff)
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if !files[0].Renamed {
		t.Error("file should be marked as renamed")
	}
	if files[0].OldPath != "old_name.go" {
		t.Errorf("expected old path old_name.go, got %s", files[0].OldPath)
	}
	if files[0].Path != "new_name.go" {
		t.Errorf("expected new path new_name.go, got %s", files[0].Path)
	}
}

func TestParse_MultipleFiles(t *testing.T) {
	diff := `diff --git a/a.go b/a.go
index abc..def 100644
--- a/a.go
+++ b/a.go
@@ -1,3 +1,4 @@
 package a

+// added
 func A() {}
diff --git a/b.go b/b.go
index abc..def 100644
--- a/b.go
+++ b/b.go
@@ -1,3 +1,4 @@
 package b

+// added
 func B() {}
`
	files := Parse(diff)
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}
	if files[0].Path != "a.go" {
		t.Errorf("expected a.go, got %s", files[0].Path)
	}
	if files[1].Path != "b.go" {
		t.Errorf("expected b.go, got %s", files[1].Path)
	}
}

func TestParse_Empty(t *testing.T) {
	files := Parse("")
	if len(files) != 0 {
		t.Errorf("expected 0 files from empty diff, got %d", len(files))
	}
}

func TestSummary(t *testing.T) {
	files := Parse(sampleDiff)
	summary := Summary(files)
	if summary == "" {
		t.Error("summary should not be empty")
	}
}

func TestLineNumbers(t *testing.T) {
	files := Parse(sampleDiff)
	h := files[0].Hunks[0]

	for _, l := range h.Lines {
		if l.Type == LineAdded && l.NewNum == 0 {
			t.Error("added lines should have non-zero NewNum")
		}
		if l.Type == LineRemoved && l.OldNum == 0 {
			t.Error("removed lines should have non-zero OldNum")
		}
	}
}
