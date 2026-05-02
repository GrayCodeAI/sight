// Package review implements the multi-concern LLM review pipeline.
package review

// Severity mirrors the public type for internal use.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// Concern defines a review focus area with its specialized prompt.
type Concern struct {
	Name   string
	Prompt string
}

// Finding is an internal finding produced by a concern review.
type Finding struct {
	Concern   string
	Severity  Severity
	File      string
	Line      int
	EndLine   int
	Message   string
	Fix       string
	Reasoning string
}

// AllConcerns returns every available concern definition.
func AllConcerns() []Concern {
	return []Concern{
		{
			Name: "security",
			Prompt: `Analyze the code changes for security vulnerabilities:
- Injection attacks (SQL, command, path traversal, template injection)
- Authentication and authorization flaws
- Sensitive data exposure (hardcoded secrets, logging credentials)
- Insecure deserialization or unsafe type assertions
- Missing input validation and sanitization
- SSRF, open redirects, CORS misconfiguration
- Race conditions that could be exploited
- Cryptographic weaknesses`,
		},
		{
			Name: "bugs",
			Prompt: `Analyze the code changes for bugs and logic errors:
- Nil/null pointer dereferences and uninitialized variables
- Off-by-one errors and boundary conditions
- Resource leaks (unclosed files, connections, channels)
- Incorrect error handling (swallowed errors, wrong error types)
- Race conditions and data races
- Integer overflow/underflow
- Incorrect boolean logic or operator precedence
- Unreachable code and dead branches
- Type assertion failures`,
		},
		{
			Name: "performance",
			Prompt: `Analyze the code changes for performance issues:
- Unnecessary allocations and copies (especially in loops)
- O(n²) or worse algorithms where O(n) or O(n log n) is possible
- Missing caching opportunities for expensive computations
- Unbounded growth (slices, maps, channels without capacity)
- Blocking operations that could be concurrent
- N+1 query patterns
- Excessive string concatenation without builders
- Missing connection/resource pooling`,
		},
		{
			Name: "correctness",
			Prompt: `Analyze the code changes for correctness issues:
- Does the code match its stated intent (function/variable names vs behavior)?
- Are all edge cases handled (empty inputs, nil, zero values)?
- Are return values and errors properly checked?
- Is concurrency handled correctly (proper locking, channel usage)?
- Are API contracts and interfaces respected?
- Are invariants maintained across the change?
- Could the change break existing callers?
- Are defer/cleanup operations in the correct order?`,
		},
		{
			Name: "style",
			Prompt: `Analyze the code changes for style and maintainability:
- Naming: do names accurately describe purpose and follow conventions?
- Complexity: are functions too long or deeply nested?
- Duplication: is there copy-paste that should be extracted?
- Abstraction level: is the code at a consistent abstraction level?
- Error messages: are they actionable and specific?
- API design: is the public surface minimal and intuitive?
- Testability: is the code structured for easy testing?`,
		},
	}
}

// BuildConcerns returns concern definitions filtered by the given names.
func BuildConcerns(names []string) []Concern {
	if len(names) == 0 {
		return AllConcerns()
	}
	all := AllConcerns()
	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}
	var result []Concern
	for _, c := range all {
		if nameSet[c.Name] {
			result = append(result, c)
		}
	}
	return result
}
