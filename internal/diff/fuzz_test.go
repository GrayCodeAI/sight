package diff

import (
	"testing"
)

func FuzzParseDiff(f *testing.F) {
	// Seed corpus from existing test cases
	f.Add(`diff --git a/main.go b/main.go
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
`)
	f.Add(`diff --git a/new.go b/new.go
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
`)
	f.Add(`diff --git a/old.go b/old.go
deleted file mode 100644
index abc1234..0000000
--- a/old.go
+++ /dev/null
@@ -1,3 +0,0 @@
-package main
-
-func oldFunc() {}
`)
	f.Add(`diff --git a/old_name.go b/new_name.go
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
`)
	f.Add("")
	f.Add("not a diff at all")
	f.Add("@@ -1,3 +1,4 @@")
	f.Add("diff --git\n")

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic on any input
		files := Parse(input)

		// Validate invariants when parsing succeeds
		for _, file := range files {
			// Path should never be empty for a successfully parsed file
			if file.Path == "" {
				t.Errorf("parsed file has empty path")
			}
			// A file cannot be both added and deleted
			if file.Added && file.Deleted {
				t.Errorf("file %q is marked as both added and deleted", file.Path)
			}
			// Validate hunk invariants
			for _, hunk := range file.Hunks {
				if hunk.OldStart < 0 {
					t.Errorf("hunk has negative OldStart: %d", hunk.OldStart)
				}
				if hunk.NewStart < 0 {
					t.Errorf("hunk has negative NewStart: %d", hunk.NewStart)
				}
				if hunk.OldCount < 0 {
					t.Errorf("hunk has negative OldCount: %d", hunk.OldCount)
				}
				if hunk.NewCount < 0 {
					t.Errorf("hunk has negative NewCount: %d", hunk.NewCount)
				}
				// Validate line invariants
				for _, line := range hunk.Lines {
					switch line.Type {
					case LineAdded:
						if line.NewNum <= 0 {
							t.Errorf("added line has non-positive NewNum: %d", line.NewNum)
						}
					case LineRemoved:
						if line.OldNum <= 0 {
							t.Errorf("removed line has non-positive OldNum: %d", line.OldNum)
						}
					case LineContext:
						if line.OldNum <= 0 {
							t.Errorf("context line has non-positive OldNum: %d", line.OldNum)
						}
						if line.NewNum <= 0 {
							t.Errorf("context line has non-positive NewNum: %d", line.NewNum)
						}
					}
				}
			}
		}
	})
}

func FuzzParseHunkHeader(f *testing.F) {
	// Seed corpus from typical hunk headers
	f.Add("@@ -1,3 +1,4 @@")
	f.Add("@@ -10,6 +10,8 @@ func main() {")
	f.Add("@@ -0,0 +1,5 @@")
	f.Add("@@ -25,4 +27,7 @@ func doSomething() {")
	f.Add("@@ -1 +1 @@")
	f.Add("@@")
	f.Add("@@ -1,3 +1,4")
	f.Add("-1,3 +1,4 @@")
	f.Add("not a hunk header")
	f.Add("")
	f.Add("@@ -999999999,999999999 +999999999,999999999 @@")
	f.Add("@@ -0,0 +0,0 @@")
	f.Add("@@ -abc,def +ghi,jkl @@")
	f.Add("@@ -1,3 +1,4 @@ extra @@ stuff @@")

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic on any input
		hunk := parseHunkHeader(input)

		// Validate invariants: counts and starts should never be negative
		// (parseHunkHeader defaults to 0 on parse errors, which is acceptable)
		if hunk.OldStart < 0 {
			t.Errorf("parseHunkHeader returned negative OldStart: %d for input %q", hunk.OldStart, input)
		}
		if hunk.NewStart < 0 {
			t.Errorf("parseHunkHeader returned negative NewStart: %d for input %q", hunk.NewStart, input)
		}
		if hunk.OldCount < 0 {
			t.Errorf("parseHunkHeader returned negative OldCount: %d for input %q", hunk.OldCount, input)
		}
		if hunk.NewCount < 0 {
			t.Errorf("parseHunkHeader returned negative NewCount: %d for input %q", hunk.NewCount, input)
		}

		// Header field should be populated (may be empty string for malformed input, that's fine)
		_ = hunk.Header
	})
}

func FuzzParseUnifiedDiff(f *testing.F) {
	// Seed corpus exercising various unified diff features
	f.Add(`diff --git a/main.go b/main.go
index abc1234..def5678 100644
--- a/main.go
+++ b/main.go
@@ -1,3 +1,4 @@
 package main

+import "fmt"
 func main() {
`)
	f.Add(`diff --git a/a.go b/a.go
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
`)
	f.Add("Binary files a/image.png and b/image.png differ\n")
	f.Add(`diff --git a/file.go b/file.go
--- a/file.go
+++ b/file.go
@@ -1,5 +1,5 @@
 line1
-line2-old
+line2-new
 line3
 line4
 line5
`)
	f.Add("random garbage\nwith no diff structure\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic on any input
		files := Parse(input)
		summary := Summary(files)

		// Summary should always return a non-empty string
		if summary == "" {
			t.Errorf("Summary returned empty string for input producing %d files", len(files))
		}

		// Validate cross-file invariants
		for _, file := range files {
			if file.Path == "" {
				t.Errorf("file has empty Path")
			}
			if file.Added && file.Deleted {
				t.Errorf("file %q is both added and deleted", file.Path)
			}
			// If renamed, OldPath and Path should differ
			if file.Renamed && file.OldPath == file.Path {
				t.Errorf("renamed file has same OldPath and Path: %q", file.Path)
			}
			// Validate each hunk's lines
			for _, hunk := range file.Hunks {
				for _, line := range hunk.Lines {
					if line.Type < LineContext || line.Type > LineRemoved {
						t.Errorf("invalid LineType %d in file %q", line.Type, file.Path)
					}
				}
			}
		}
	})
}
