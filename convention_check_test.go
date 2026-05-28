package sight

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 1. Naming conventions -- detection of non-conventional variable/function names
// ---------------------------------------------------------------------------

func TestCheck_NamingConventionSnakeCaseInGo(t *testing.T) {
	// Go code should use camelCase, not snake_case.
	convs := []Convention{
		{
			Name:        "go-no-snake-case",
			Description: "Go code should use camelCase, not snake_case",
			Pattern:     `\b[a-z]+_[a-z]+\b`,
			FilePattern: "*.go",
			Severity:    SeverityMedium,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/handler.go\n+func do_something() {\n+\tmy_var := 1\n+}\n"
	findings := cc.Check(diff)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for snake_case names, got %d", len(findings))
	}
	for _, f := range findings {
		if f.File != "handler.go" {
			t.Errorf("expected file handler.go, got %s", f.File)
		}
		if !strings.Contains(f.Message, "go-no-snake-case") {
			t.Errorf("expected message to contain convention name, got %s", f.Message)
		}
	}
}

func TestCheck_NamingConventionAllCapsNonConst(t *testing.T) {
	// Detect ALL_CAPS identifiers that may be non-const in Go.
	convs := []Convention{
		{
			Name:        "go-no-all-caps-vars",
			Description: "Avoid ALL_CAPS except for constants",
			Pattern:     `\b[A-Z][A-Z_]{2,}\b`,
			FilePattern: "*.go",
			Severity:    SeverityLow,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/config.go\n+var MAX_RETRIES = 3\n"
	findings := cc.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("expected SeverityLow, got %v", findings[0].Severity)
	}
}

func TestCheck_NamingConventionHungarianNotation(t *testing.T) {
	// Detect Hungarian notation prefixes (e.g. strName, intCount).
	convs := []Convention{
		{
			Name:        "no-hungarian",
			Description: "Do not use Hungarian notation",
			Pattern:     `\b(str|int|bool|flt|arr|obj|ptr)[A-Z][a-zA-Z]+\b`,
			Severity:    SeverityMedium,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/util.ts\n+const strName = \"hello\"\n+const intCount = 5\n"
	findings := cc.Check(diff)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for Hungarian notation, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// 2. Import conventions -- detection of incorrect import patterns
// ---------------------------------------------------------------------------

func TestCheck_ImportConventionNoWildcardImport(t *testing.T) {
	// Detect wildcard imports in Go (e.g. "import . \"fmt\"").
	convs := []Convention{
		{
			Name:        "go-no-dot-import",
			Description: "Avoid dot imports in Go",
			Pattern:     `import\s+\.\s+"`,
			FilePattern: "*.go",
			Severity:    SeverityHigh,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/main.go\n+import . \"fmt\"\n+fmt.Println(\"hello\")\n"
	findings := cc.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for dot import, got %d", len(findings))
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", findings[0].Severity)
	}
}

func TestCheck_ImportConventionNoTestImportInProd(t *testing.T) {
	// Detect testing package imports in non-test Go files.
	convs := []Convention{
		{
			Name:        "no-test-import-in-prod",
			Description: "Do not import testing in production code",
			Pattern:     `"testing"`,
			FilePattern: "*.go",
			Severity:    SeverityCritical,
		},
	}
	cc := NewConventionChecker(convs)

	// Non-test file importing testing -- violation.
	diff := "+++ b/handler.go\n+import \"testing\"\n"
	findings := cc.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	// Test file importing testing -- not checked because FilePattern is *.go
	// but the checker doesn't distinguish _test.go from .go. This is expected
	// because we only set *.go which matches both.
	diffTest := "+++ b/handler_test.go\n+import \"testing\"\n"
	findingsTest := cc.Check(diffTest)
	// *.go glob matches handler_test.go too, so this should flag.
	if len(findingsTest) != 1 {
		t.Fatalf("expected 1 finding for test file too (glob matches), got %d", len(findingsTest))
	}
}

func TestCheck_ImportConventionPythonRelativeImports(t *testing.T) {
	// Detect relative imports in Python (from . import X).
	convs := []Convention{
		{
			Name:        "python-no-relative-import",
			Description: "Use absolute imports, not relative",
			Pattern:     `from\s+\.\s+import`,
			FilePattern: "*.py",
			Severity:    SeverityMedium,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/app/utils.py\n+from . import helpers\n"
	findings := cc.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for relative import, got %d", len(findings))
	}
}

func TestCheck_ImportConventionTypeScriptDefaultImport(t *testing.T) {
	// Detect default imports from certain modules in TypeScript.
	convs := []Convention{
		{
			Name:        "ts-no-lodash-default",
			Description: "Use named imports from lodash, not default",
			Pattern:     `import\s+\w+\s+from\s+['"]lodash['"]`,
			FilePattern: "*.ts",
			Severity:    SeverityMedium,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/src/utils.ts\n+import _ from 'lodash'\n"
	findings := cc.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// 3. File organization -- detection of files that don't follow conventions
// ---------------------------------------------------------------------------

func TestCheck_FileOrganizationLargeFile(t *testing.T) {
	// Warn when a file exceeds a size threshold (e.g., >500 lines).
	// We simulate this by matching a marker comment convention.
	convs := []Convention{
		{
			Name:        "no-todo-fixme",
			Description: "No TODO/FIXME in committed code",
			Pattern:     `(TODO|FIXME|HACK)\b`,
			Severity:    SeverityLow,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/big_module.go\n+// TODO: refactor this later\n+func main() {}\n+// FIXME: broken logic\n"
	findings := cc.Check(diff)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for TODO and FIXME, got %d", len(findings))
	}
}

func TestCheck_FileOrganizationSpecificDirectory(t *testing.T) {
	// The matchGlob helper supports: "*" (any), "*.ext" (by extension),
	// and substring matching. Use a substring pattern to filter by directory.
	convs := []Convention{
		{
			Name:        "no-console-log-in-src",
			Description: "No console.log in src/ files",
			Pattern:     `console\.log\(`,
			FilePattern: "src/", // substring match
			Severity:    SeverityMedium,
		},
	}
	cc := NewConventionChecker(convs)

	// Should flag in src/.
	diff := "+++ b/src/app.ts\n+console.log(\"debug\")\n"
	findings := cc.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding in src/, got %d", len(findings))
	}

	// Should NOT flag in test/.
	diffTest := "+++ b/test/app.test.ts\n+console.log(\"debug\")\n"
	findingsTest := cc.Check(diffTest)
	if len(findingsTest) != 0 {
		t.Fatalf("expected 0 findings in test/, got %d", len(findingsTest))
	}
}

func TestCheck_FileOrganizationMixedExtensions(t *testing.T) {
	// Check that file pattern filtering works across different file types.
	convs := []Convention{
		{
			Name:        "no-debug-print",
			Description: "No debug print statements",
			Pattern:     `fmt\.Println\(debug`,
			FilePattern: "*.go",
			Severity:    SeverityLow,
		},
		{
			Name:        "no-python-print-debug",
			Description: "No print('debug') in Python",
			Pattern:     `print\(.*debug`,
			FilePattern: "*.py",
			Severity:    SeverityLow,
		},
	}
	cc := NewConventionChecker(convs)

	// Go file -- should flag.
	diffGo := "+++ b/main.go\n+fmt.Println(debug)\n"
	if len(cc.Check(diffGo)) != 1 {
		t.Error("expected finding for Go debug print")
	}

	// Python file -- should flag.
	diffPy := "+++ b/app.py\n+print('debug info')\n"
	if len(cc.Check(diffPy)) != 1 {
		t.Error("expected finding for Python debug print")
	}

	// TypeScript file -- should NOT flag either convention.
	diffTS := "+++ b/index.ts\n+console.log('debug')\n"
	if len(cc.Check(diffTS)) != 0 {
		t.Error("expected 0 findings for TS (conventions target .go and .py)")
	}
}

// ---------------------------------------------------------------------------
// 4. Custom rules -- test that custom convention rules work
// ---------------------------------------------------------------------------

func TestConventionsFromStrings_NeverUse(t *testing.T) {
	// extractPhrase takes everything up to the first punctuation or end,
	// so "Never use var" extracts "var" (the whole rest of the string).
	rules := []string{
		"Never use var",
	}
	convs := ConventionsFromStrings(rules)

	if len(convs) != 1 {
		t.Fatalf("expected 1 convention, got %d", len(convs))
	}
	conv := convs[0]
	if conv.Name != "no-var" {
		t.Errorf("expected name 'no-var', got '%s'", conv.Name)
	}
	if conv.Pattern == "" {
		t.Error("expected non-empty pattern")
	}

	// Verify the generated pattern works.
	cc := NewConventionChecker(convs)
	diff := "+++ b/main.go\n+var x = 5\n"
	findings := cc.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for 'var', got %d", len(findings))
	}
}

func TestConventionsFromStrings_NeverUseWithSuffix(t *testing.T) {
	// extractPhrase truncates at the first punctuation character.
	// "Never use fmt.Println" -- the period in "fmt.Println" truncates to "fmt".
	rules := []string{
		"Never use fmt.Println; use a logger instead",
	}
	convs := ConventionsFromStrings(rules)

	if len(convs) != 1 {
		t.Fatalf("expected 1 convention, got %d", len(convs))
	}
	if convs[0].Name != "no-fmt" {
		t.Errorf("expected name 'no-fmt', got '%s'", convs[0].Name)
	}
}

func TestConventionsFromStrings_DontUse(t *testing.T) {
	rules := []string{
		"Don't use panic",
	}
	convs := ConventionsFromStrings(rules)

	if len(convs) != 1 {
		t.Fatalf("expected 1 convention, got %d", len(convs))
	}
	if convs[0].Name != "avoid-panic" {
		t.Errorf("expected name 'avoid-panic', got '%s'", convs[0].Name)
	}
}

func TestConventionsFromStrings_Avoid(t *testing.T) {
	rules := []string{
		"Avoid global variables",
	}
	convs := ConventionsFromStrings(rules)

	if len(convs) != 1 {
		t.Fatalf("expected 1 convention, got %d", len(convs))
	}
	if convs[0].Name != "avoid-global-variables" {
		t.Errorf("expected name 'avoid-global-variables', got '%s'", convs[0].Name)
	}
}

func TestConventionsFromStrings_UseXNotY(t *testing.T) {
	rules := []string{
		"Use errors.New not fmt.Errorf for simple errors",
	}
	convs := ConventionsFromStrings(rules)

	if len(convs) != 1 {
		t.Fatalf("expected 1 convention, got %d", len(convs))
	}
	if convs[0].Name != "prefer-alternative" {
		t.Errorf("expected name 'prefer-alternative', got '%s'", convs[0].Name)
	}

	// The pattern should detect fmt.Errorf (the "not" part).
	cc := NewConventionChecker(convs)
	diff := "+++ b/err.go\n+return fmt.Errorf(\"bad\")\n"
	findings := cc.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for fmt.Errorf, got %d", len(findings))
	}
}

func TestConventionsFromStrings_MultipleRules(t *testing.T) {
	rules := []string{
		"Never use panic",
		"Avoid goroutine leaks",
		"Don't use init() functions",
	}
	convs := ConventionsFromStrings(rules)

	if len(convs) != 3 {
		t.Fatalf("expected 3 conventions, got %d", len(convs))
	}
}

func TestConventionsFromStrings_EmptyRules(t *testing.T) {
	convs := ConventionsFromStrings([]string{})
	if len(convs) != 0 {
		t.Fatalf("expected 0 conventions, got %d", len(convs))
	}
}

func TestConventionsFromStrings_UnrecognizedRule(t *testing.T) {
	// A rule that doesn't match any known pattern.
	convs := ConventionsFromStrings([]string{"always be kind"})
	if len(convs) != 0 {
		t.Fatalf("expected 0 conventions for unrecognized rule, got %d", len(convs))
	}
}

func TestConventionsFromStrings_PunctuationTruncation(t *testing.T) {
	rules := []string{
		"Never use var; always use const or let",
	}
	convs := ConventionsFromStrings(rules)

	if len(convs) != 1 {
		t.Fatalf("expected 1 convention, got %d", len(convs))
	}
	// "var" should be extracted up to the semicolon.
	if convs[0].Name != "no-var" {
		t.Errorf("expected name 'no-var', got '%s'", convs[0].Name)
	}
}

// ---------------------------------------------------------------------------
// 5. Language-specific -- Go, Python, TypeScript conventions separately
// ---------------------------------------------------------------------------

func TestCheck_GolangSpecificNoDeferInLoop(t *testing.T) {
	convs := []Convention{
		{
			Name:        "go-no-defer-in-loop",
			Description: "Do not use defer inside loops",
			Pattern:     `defer\s+\w+`,
			FilePattern: "*.go",
			Severity:    SeverityHigh,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/loop.go\n+for i := 0; i < 10; i++ {\n+\tdefer cleanup(i)\n+}\n"
	findings := cc.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for defer in loop, got %d", len(findings))
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", findings[0].Severity)
	}
}

func TestCheck_PythonSpecificNoBareExcept(t *testing.T) {
	convs := []Convention{
		{
			Name:        "python-no-bare-except",
			Description: "Use specific exceptions, not bare except",
			Pattern:     `except\s*:`,
			FilePattern: "*.py",
			Severity:    SeverityHigh,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/app.py\n+try:\n+\tpass\n+except:\n+\tpass\n"
	findings := cc.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for bare except, got %d", len(findings))
	}
}

func TestCheck_PythonSpecificNoMutableDefault(t *testing.T) {
	convs := []Convention{
		{
			Name:        "python-no-mutable-default",
			Description: "Do not use mutable default arguments",
			Pattern:     `def\s+\w+\([^)]*=\s*(\[\]|\{\})`,
			FilePattern: "*.py",
			Severity:    SeverityHigh,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/utils.py\n+def foo(items=[]):\n+\tpass\n"
	findings := cc.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for mutable default, got %d", len(findings))
	}
}

func TestCheck_TypeScriptSpecificNoAny(t *testing.T) {
	convs := []Convention{
		{
			Name:        "ts-no-any",
			Description: "Avoid using the 'any' type",
			Pattern:     `:\s*any\b`,
			FilePattern: "*.ts",
			Severity:    SeverityMedium,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/src/types.ts\n+let value: any = getData()\n"
	findings := cc.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for 'any' type, got %d", len(findings))
	}
}

func TestCheck_TypeScriptSpecificNoEnum(t *testing.T) {
	convs := []Convention{
		{
			Name:        "ts-no-enum",
			Description: "Use const objects instead of enum",
			Pattern:     `\benum\s+\w+`,
			FilePattern: "*.ts",
			Severity:    SeverityMedium,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/src/constants.ts\n+enum Status {\n+\tActive = \"active\"\n+}\n"
	findings := cc.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for enum, got %d", len(findings))
	}
}

func TestCheck_GolangSpecificFileIgnored(t *testing.T) {
	// Python convention should NOT fire on Go files.
	convs := []Convention{
		{
			Name:        "python-no-bare-except",
			Description: "Use specific exceptions, not bare except",
			Pattern:     `except\s*:`,
			FilePattern: "*.py",
			Severity:    SeverityHigh,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/handler.go\n+except:\n"
	findings := cc.Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (Python rule on .go file), got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// 6. Pre-compiled regexes -- test that patterns are compiled correctly
// ---------------------------------------------------------------------------

func TestNewConventionChecker_PreCompilesRegexes(t *testing.T) {
	convs := []Convention{
		{
			Name:    "test-pattern",
			Pattern: `\bfoo\b`,
		},
		{
			Name:    "no-pattern",
			Pattern: "", // empty -- should not attempt compile
		},
	}
	cc := NewConventionChecker(convs)

	if cc.conventions[0].compiledRe == nil {
		t.Error("expected compiledRe to be set for convention with pattern")
	}
	if cc.conventions[1].compiledRe != nil {
		t.Error("expected compiledRe to be nil for convention with empty pattern")
	}
}

func TestNewConventionChecker_InvalidRegexSkipped(t *testing.T) {
	// Invalid regex should not crash; it just won't match.
	convs := []Convention{
		{
			Name:    "bad-regex",
			Pattern: `[invalid`, // unclosed bracket
		},
	}
	cc := NewConventionChecker(convs)

	if cc.conventions[0].compiledRe != nil {
		t.Error("expected compiledRe to be nil for invalid regex")
	}

	// Should produce zero findings (no compiled regex to match).
	diff := "+++ b/test.go\n+anything\n"
	findings := cc.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for invalid regex, got %d", len(findings))
	}
}

func TestPreCompiledRegex_CaseInsensitive(t *testing.T) {
	convs := []Convention{
		{
			Name:    "case-insensitive",
			Pattern: `(?i)\bpanic\b`,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/main.go\n+PANIC(\"oh no\")\n+panic(\"oh no\")\n+Panic(\"oh no\")\n"
	findings := cc.Check(diff)

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings for case-insensitive match, got %d", len(findings))
	}
}

func TestPreCompiledRegex_WordBoundary(t *testing.T) {
	convs := []Convention{
		{
			Name:    "exact-word",
			Pattern: `\bvar\b`,
		},
	}
	cc := NewConventionChecker(convs)

	// "var" should match; "variable" should not.
	diff := "+++ b/main.go\n+var x = 1\n+variable := \"hello\"\n"
	findings := cc.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (word boundary), got %d", len(findings))
	}
}

func TestPreCompiledRegex_ComplexPattern(t *testing.T) {
	// Test a more complex regex with alternation and quantifiers.
	convs := []Convention{
		{
			Name:    "no-hardcoded-ports",
			Pattern: `:\d{4,5}\b`,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/server.go\n+addr := \":8080\"\n+port := 3000\n"
	findings := cc.Check(diff)

	// Both ":8080" and "3000" contain 4-5 digit numbers preceded by colon.
	// ":8080" matches `:\d{4,5}`, and ":3000" is part of "port := 3000" which
	// does NOT have a colon before 3000 (there's ":= " before it).
	// Actually let's check: "port := 3000" -- the `:\d{4,5}` would match ": 3000"? No,
	// because there's a space after the colon. So only ":8080" matches.
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for hardcoded port, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Edge cases and helper function tests
// ---------------------------------------------------------------------------

func TestCheck_EmptyDiff(t *testing.T) {
	convs := []Convention{
		{
			Name:    "test",
			Pattern: `\bfoo\b`,
		},
	}
	cc := NewConventionChecker(convs)

	findings := cc.Check("")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty diff, got %d", len(findings))
	}
}

func TestCheck_NoConventions(t *testing.T) {
	cc := NewConventionChecker(nil)

	diff := "+++ b/main.go\n+var x = 1\n"
	findings := cc.Check(diff)
	if findings != nil {
		t.Fatalf("expected nil findings for nil conventions, got %v", findings)
	}
}

func TestCheck_EmptyConventions(t *testing.T) {
	cc := NewConventionChecker([]Convention{})

	diff := "+++ b/main.go\n+var x = 1\n"
	findings := cc.Check(diff)
	if findings != nil {
		t.Fatalf("expected nil findings for empty conventions, got %v", findings)
	}
}

func TestCheck_OnlyAddedLinesChecked(t *testing.T) {
	convs := []Convention{
		{
			Name:    "no-panic",
			Pattern: `\bpanic\b`,
		},
	}
	cc := NewConventionChecker(convs)

	// Removed line (starts with -) should NOT be checked.
	diff := "+++ b/main.go\n-panic(\"removed\")\n+fmt.Println(\"added\")\n"
	findings := cc.Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (removed line), got %d", len(findings))
	}
}

func TestCheck_ContextLinesIgnored(t *testing.T) {
	convs := []Convention{
		{
			Name:    "no-panic",
			Pattern: `\bpanic\b`,
		},
	}
	cc := NewConventionChecker(convs)

	// Context line (starts with space) should NOT be checked.
	diff := "+++ b/main.go\n panic(\"context\")\n"
	findings := cc.Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (context line), got %d", len(findings))
	}
}

func TestCheck_NoFileHeader(t *testing.T) {
	convs := []Convention{
		{
			Name:        "no-panic",
			Pattern:     `\bpanic\b`,
			FilePattern: "*.go",
		},
	}
	cc := NewConventionChecker(convs)

	// Without a +++ header, currentFile is "" which won't match "*.go".
	diff := "+panic(\"test\")\n"
	findings := cc.Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without file header, got %d", len(findings))
	}
}

func TestCheck_MultipleFiles(t *testing.T) {
	convs := []Convention{
		{
			Name:    "no-panic",
			Pattern: `\bpanic\b`,
		},
	}
	cc := NewConventionChecker(convs)

	diff := strings.Join([]string{
		"+++ b/main.go",
		"+panic(\"first\")",
		"+++ b/handler.go",
		"+panic(\"second\")",
	}, "\n")

	findings := cc.Check(diff)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings across 2 files, got %d", len(findings))
	}
	if findings[0].File != "main.go" {
		t.Errorf("expected first finding in main.go, got %s", findings[0].File)
	}
	if findings[1].File != "handler.go" {
		t.Errorf("expected second finding in handler.go, got %s", findings[1].File)
	}
}

func TestCheck_SeverityPreserved(t *testing.T) {
	convs := []Convention{
		{
			Name:     "critical-rule",
			Pattern:  `\bDANGER\b`,
			Severity: SeverityCritical,
		},
		{
			Name:     "info-rule",
			Pattern:  `\bNOTE\b`,
			Severity: SeverityInfo,
		},
	}
	cc := NewConventionChecker(convs)

	diff := "+++ b/main.go\n+// DANGER: do not touch\n+// NOTE: this is fine\n"
	findings := cc.Check(diff)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", findings[0].Severity)
	}
	if findings[1].Severity != SeverityInfo {
		t.Errorf("expected SeverityInfo, got %v", findings[1].Severity)
	}
}

func TestCheck_DefaultSeverityFromStrings(t *testing.T) {
	// ConventionsFromStrings should default to SeverityMedium.
	convs := ConventionsFromStrings([]string{"Never use alert"})
	if len(convs) != 1 {
		t.Fatalf("expected 1 convention, got %d", len(convs))
	}
	if convs[0].Severity != SeverityMedium {
		t.Errorf("expected default SeverityMedium, got %v", convs[0].Severity)
	}
}

func TestMatchGlob_Wildcard(t *testing.T) {
	if !matchGlob("anything.go", "*") {
		t.Error("* should match anything")
	}
}

func TestMatchGlob_Extension(t *testing.T) {
	if !matchGlob("main.go", "*.go") {
		t.Error("*.go should match main.go")
	}
	if matchGlob("main.py", "*.go") {
		t.Error("*.go should not match main.py")
	}
}

func TestMatchGlob_ContainsPattern(t *testing.T) {
	if !matchGlob("src/utils/helper.go", "utils") {
		t.Error("'utils' should match path containing 'utils'")
	}
	if matchGlob("src/lib/helper.go", "utils") {
		t.Error("'utils' should not match path without 'utils'")
	}
}

func TestExtractPhrase_Punctuation(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"var; use const", "var"},
		{"panic. just don't", "panic"},
		{"  spaces  ", "spaces"},
		{"longphrase", "longphrase"},
	}
	for _, tt := range tests {
		got := extractPhrase(tt.input)
		if got != tt.want {
			t.Errorf("extractPhrase(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractPhrase_MaxLength(t *testing.T) {
	long := strings.Repeat("a", 50)
	got := extractPhrase(long)
	if len(got) > 40 {
		t.Errorf("expected max 40 chars, got %d", len(got))
	}
}

func TestSecurityConcerns_ReturnsNonEmpty(t *testing.T) {
	concerns := SecurityConcerns()
	if len(concerns) == 0 {
		t.Error("expected non-empty security concerns list")
	}
	// Spot-check some expected entries.
	found := map[string]bool{}
	for _, c := range concerns {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "sql injection") {
			found["sql"] = true
		}
		if strings.Contains(lower, "xss") {
			found["xss"] = true
		}
		if strings.Contains(lower, "hardcoded secret") {
			found["secrets"] = true
		}
	}
	for _, key := range []string{"sql", "xss", "secrets"} {
		if !found[key] {
			t.Errorf("expected SecurityConcerns to contain %s-related entry", key)
		}
	}
}
