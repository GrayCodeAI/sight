package eval

import (
	"testing"
)

func TestSuiteManager(t *testing.T) {
	m := NewSuiteManager()

	if m == nil {
		t.Fatal("expected non-nil manager")
	}

	if len(m.List()) != 0 {
		t.Errorf("expected 0 suites, got %d", len(m.List()))
	}
}

func TestRegisterSuite(t *testing.T) {
	m := NewSuiteManager()

	suite := &Suite{
		Name:        "test-suite",
		Description: "A test suite",
		Tests: []*Test{
			{
				Name:        "test-1",
				Description: "Test 1",
				Command:     "go test",
				Args:        []string{"./..."},
				Expected: ExpectedResult{
					ExitCode: 0,
					Output:   "PASS",
				},
			},
		},
	}

	m.Register(suite)

	got := m.FindSuite("test-suite")
	if got == nil {
		t.Fatal("expected to find suite")
	}

	if got.Name != "test-suite" {
		t.Errorf("expected suite name 'test-suite', got %s", got.Name)
	}
}

func TestListSuites(t *testing.T) {
	m := NewSuiteManager()

	suite1 := &Suite{Name: "suite-1"}
	suite2 := &Suite{Name: "suite-2"}

	m.Register(suite1)
	m.Register(suite2)

	suites := m.List()
	if len(suites) != 2 {
		t.Errorf("expected 2 suites, got %d", len(suites))
	}
}

func TestRunTest(t *testing.T) {
	m := NewSuiteManager()

	test := &Test{
		Name:        "test-command",
		Description: "Runs a command",
		Command:     "echo",
		Args:        []string{"hello"},
		Expected: ExpectedResult{
			Output: "hello\n",
		},
	}

	result := m.RunTest(test)
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if !result.Passed {
		t.Logf("Test output: %s", result.Output)
		if result.Error != nil {
			t.Logf("Test error: %v", result.Error)
		}
	}
}

func TestSummarize(t *testing.T) {
	m := NewSuiteManager()

	results := []*Result{
		{Test: &Test{Name: "t1"}, Passed: true, DurationMs: 100},
		{Test: &Test{Name: "t2"}, Passed: false, DurationMs: 200},
		{Test: &Test{Name: "t3"}, Passed: true, DurationMs: 150},
	}

	summary := m.Summarize(results, 450)
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}

	if summary.TotalTests != 3 {
		t.Errorf("expected 3 total tests, got %d", summary.TotalTests)
	}

	if summary.PassedTests != 2 {
		t.Errorf("expected 2 passed tests, got %d", summary.PassedTests)
	}

	if summary.FailedTests != 1 {
		t.Errorf("expected 1 failed test, got %d", summary.FailedTests)
	}

	if summary.PassRate < 66 || summary.PassRate > 67 {
		t.Errorf("expected pass rate ~66.67, got %f", summary.PassRate)
	}
}

func TestBuiltinSuites(t *testing.T) {
	m := NewSuiteManager()
	builtin := BuiltinSuites()

	for _, suite := range builtin {
		m.Register(&suite)
	}

	suites := m.List()
	if len(suites) != len(builtin) {
		t.Errorf("expected %d builtin suites, got %d", len(builtin), len(suites))
	}
}
