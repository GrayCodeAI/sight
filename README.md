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
- SARIF (static analysis interchange)
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
