// Package eval provides builtin evaluation suites.
package eval

// BuiltinSuites returns default evaluation suites.
func BuiltinSuites() []Suite {
	return []Suite{
		{
			Name:        "unit-tests",
			Description: "Run all unit tests",
			Tests: []*Test{
				{
					Name:        "graph-package",
					Description: "Run graph package tests",
					Command:     "go",
					Args:        []string{"test", "github.com/GrayCodeAI/sight/internal/graph/...", "-v"},
					Expected: ExpectedResult{
						ExitCode: 0,
					},
				},
				{
					Name:        "audit-package",
					Description: "Run audit package tests",
					Command:     "go",
					Args:        []string{"test", "github.com/GrayCodeAI/sight/internal/audit/...", "-v"},
					Expected: ExpectedResult{
						ExitCode: 0,
					},
				},
				{
					Name:        "tool-package",
					Description: "Run tool package tests",
					Command:     "go",
					Args:        []string{"test", "github.com/GrayCodeAI/sight/internal/tool/...", "-v"},
					Expected: ExpectedResult{
						ExitCode: 0,
					},
				},
			},
		},
	}
}
