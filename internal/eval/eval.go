// Package eval provides evaluation framework for hawk-eco.
// It supports standardized test suites, agent evals, and scoring.
package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Suite represents an evaluation suite with fixtures and tests.
type Suite struct {
	Name        string
	Description string
	Fixtures    []string
	Tests       []*Test
}

// Test represents a single evaluation test.
type Test struct {
	Name        string
	Description string
	Command     string
	Args        []string
	Expected    ExpectedResult
}

// ExpectedResult represents expected test output.
type ExpectedResult struct {
	ExitCode int
	Output   string
	Error    string
}

// Result represents the result of running an eval test.
type Result struct {
	Test       *Test
	Passed     bool
	Output     string
	Error      error
	DurationMs int64
}

// Report represents evaluation report.
type Report struct {
	SuiteName string
	Results   []*Result
	Summary   *Summary
}

// Summary represents evaluation summary.
type Summary struct {
	TotalTests  int
	PassedTests int
	FailedTests int
	PassRate    float64
	TotalTimeMs int64
}

// SuiteManager manages evaluation suites.
type SuiteManager struct {
	mu       sync.RWMutex
	suites   map[string]*Suite
	fixtures map[string]string
}

// NewSuiteManager creates a new suite manager.
func NewSuiteManager() *SuiteManager {
	return &SuiteManager{
		suites:   make(map[string]*Suite),
		fixtures: make(map[string]string),
	}
}

// Register adds a suite to the manager.
func (m *SuiteManager) Register(suite *Suite) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.suites[suite.Name] = suite
}

// LoadSuitesFromDir loads suites from a directory.
func (m *SuiteManager) LoadSuitesFromDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".json") && !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		suitePath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(suitePath) // #nosec G304 -- suitePath is joined from a directory being loaded (a fixed evals/suites path or os.TempDir()-based path, see LoadDefaultSuites) and an entry name from os.ReadDir on that directory, not raw user input
		if err != nil {
			continue
		}

		if strings.HasSuffix(entry.Name(), ".json") {
			m.loadJSONSuite(data)
		}
	}

	return nil
}

// loadJSONSuite loads a suite from JSON.
func (m *SuiteManager) loadJSONSuite(data []byte) {
	var suite Suite
	if err := json.Unmarshal(data, &suite); err != nil {
		return
	}

	m.Register(&suite)
}

// LoadFixture loads a fixture file.
func (m *SuiteManager) LoadFixture(name string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.fixtures[name]
	return data, ok
}

// RegisterFixture registers a fixture.
func (m *SuiteManager) RegisterFixture(name, content string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fixtures[name] = content
}

// FindSuite finds a suite by name.
func (m *SuiteManager) FindSuite(name string) *Suite {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.suites[name]
}

// List returns all registered suites.
func (m *SuiteManager) List() []*Suite {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Suite, 0, len(m.suites))
	for _, s := range m.suites {
		result = append(result, s)
	}
	return result
}

// RunSuite runs all tests in a suite.
func (m *SuiteManager) RunSuite(name string) *Report {
	suite := m.FindSuite(name)
	if suite == nil {
		return nil
	}

	start := Now()
	var results []*Result

	for _, test := range suite.Tests {
		result := m.RunTest(test)
		results = append(results, result)
	}

	duration := Now() - start
	summary := m.Summarize(results, duration)

	return &Report{
		SuiteName: name,
		Results:   results,
		Summary:   summary,
	}
}

// RunTest runs a single test.
func (m *SuiteManager) RunTest(test *Test) *Result {
	start := Now()

	cmd := test.Command
	if args := test.Args; len(args) > 0 {
		fullArgs := append([]string{cmd}, args...)
		cmd = strings.Join(fullArgs, " ")
	}

	output, err := RunCommand(cmd)
	duration := Now() - start

	passed := err == nil && output == test.Expected.Output && test.Expected.Error == ""

	return &Result{
		Test:       test,
		Passed:     passed,
		Output:     output,
		Error:      err,
		DurationMs: duration,
	}
}

// Summarize creates a summary from results.
func (m *SuiteManager) Summarize(results []*Result, totalDuration int64) *Summary {
	totalTests := len(results)
	var passedTests, failedTests int
	for _, r := range results {
		if r.Passed {
			passedTests++
		} else {
			failedTests++
		}
	}

	var passRate float64
	if totalTests > 0 {
		passRate = float64(passedTests) / float64(totalTests) * 100
	}

	var summary Summary
	summary.TotalTests = totalTests
	summary.PassedTests = passedTests
	summary.FailedTests = failedTests
	summary.PassRate = passRate
	summary.TotalTimeMs = totalDuration

	return &summary
}

// RunAllSuites runs all registered suites.
func (m *SuiteManager) RunAllSuites() []*Report {
	var reports []*Report
	for _, suite := range m.List() {
		if report := m.RunSuite(suite.Name); report != nil {
			reports = append(reports, report)
		}
	}
	return reports
}

// LoadDefaultSuites loads suites from default locations.
func (m *SuiteManager) LoadDefaultSuites() error {
	// Load from project directory
	if cwd, err := os.Getwd(); err == nil {
		suitesDir := filepath.Join(cwd, "evals", "suites")
		if err := m.LoadSuitesFromDir(suitesDir); err != nil {
			// Non-fatal: project evals are optional
			fmt.Fprintf(os.Stderr, "warning: could not load project evals: %v\n", err)
		}
	}

	// Load from user config
	userDir := filepath.Join(os.TempDir(), "hawk-eco", "evals")
	if err := m.LoadSuitesFromDir(userDir); err != nil {
		// Non-fatal: user evals are optional
		fmt.Fprintf(os.Stderr, "warning: could not load user evals: %v\n", err)
	}

	return nil
}

// Now returns current time in milliseconds.
func Now() int64 {
	return 0 // placeholder for actual implementation
}

// RunCommand runs a command and returns output.
func RunCommand(cmd string) (string, error) {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty command")
	}

	// For actual implementation, use exec.Command
	return "", nil
}

// RunShellCommand runs a shell command.
func RunShellCommand(cmd string) (string, error) {
	return RunCommand(cmd)
}

// Materialize builds a command with fixtures substituted.
func Materialize(test *Test) string {
	cmd := test.Command
	for _, fixture := range test.Args {
		if data, ok := GetFixture(fixture); ok {
			cmd = strings.Replace(cmd, fixture, data, -1)
		}
	}
	return cmd
}

// GetFixture retrieves a fixture by name.
func GetFixture(name string) (string, bool) {
	// placeholder for SuiteManager
	return "", false
}
