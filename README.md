# sight

AI-powered code review on diffs. Parses unified diffs, enriches with surrounding code context and git history, then runs parallel multi-concern reviews through an LLM provider.

## Design

- **Library only** — no CLI, no binary
- **No LLM SDK dependency** — defines a Provider interface; consumers implement it
- **No opinions** — consumers inject their own LLM client (e.g., via eyrie)

## Install

```bash
go get github.com/GrayCodeAI/sight@latest
```

## Usage

### One-shot review

```go
result, err := sight.Review(ctx, diffText,
    sight.WithProvider(myProvider),
    sight.Thorough,
)
for _, f := range result.Findings {
    fmt.Printf("[%s] %s:%d - %s\n", f.Severity, f.File, f.Line, f.Message)
}
```

### Reusable reviewer

```go
r := sight.NewReviewer(sight.WithProvider(p), sight.Thorough)
result1, _ := r.Review(ctx, diff1)
result2, _ := r.Review(ctx, diff2)
```

### Provider interface

Implement this with any LLM client:

```go
type Provider interface {
    Complete(ctx context.Context, messages []Message) (string, error)
}
```

## Presets

| Preset | Concerns | Use case |
|--------|----------|----------|
| Quick | security, correctness | Fast PR checks |
| Standard | all (default) | Balanced review |
| Thorough | all + deeper analysis | Critical code |
| SecurityFocus | security only | Security audit |
| CI | all + fail-on threshold | CI/CD gates |

## Findings

Each finding includes:
- **Concern**: security, performance, correctness, maintainability, testing
- **Severity**: critical, high, medium, low, info
- **File** and **Line**: exact location in diff
- **Message**: human-readable description
- **Fix**: suggested code fix
- **CWE**: reference (e.g., CWE-79)

## Output Formats

- Inline comments (GitHub/GitLab PR comments)
- Human-readable terminal output

## Configuration

File-based config via `.sight.toml`:

```toml
fail-on = "high"
exclude = ["vendor/", "generated/"]
concerns = ["security", "performance", "correctness"]
```

## Testing

```bash
make test        # Unit tests
make test-race   # With race detector
make bench       # Benchmarks
make cover       # Coverage report
```

## License

MIT

## New Features (Wave 1-4)

### Confidence Scoring

Every finding includes a numeric confidence score (0.0-1.0) indicating how certain the system is that it's a true positive. Higher scores = more reliable findings.

### SAST-LLM Fusion

Sight can ingest findings from static analysis tools (SAST) and feed them into the LLM review prompt for validation. This combines the breadth of automated scanning with the depth of LLM reasoning.

### Fix Suggestion Pipeline

Sight includes a built-in fix suggestion pipeline that generates remediation code for common vulnerability patterns:
- SQL injection → parameterized queries
- XSS → HTML escaping / template engines
- Hardcoded secrets → environment variables
- Missing input validation → validation middleware
- Weak crypto → modern algorithm replacement
- Path traversal → filepath.Clean + base path checks
- SSRF → URL allowlist validation

Custom rules can be registered via AddRule().

### Memory Bridge (Coming Soon)

Integration with yaad memory for context-aware reviews. Sight can recall similar past findings and store review results for future reference.

## Ecosystem

Sight is part of the hawk-eco platform:
- **hawk** — CLI/REPL that orchestrates all tools
- **eyrie** — LLM provider layer (sight calls LLMs through eyrie)
- **yaad** — memory/recall engine
- **inspect** — security/accessibility auditing
- **tok** — token counting and cost estimation
- **trace** — session capture and replay
