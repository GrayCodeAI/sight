# Contributing to sight

## Setup

```bash
git clone https://github.com/GrayCodeAI/sight.git
cd sight
make test
```

## Requirements

- Go 1.26+
- No external dependencies beyond mcp-go

## Development

```bash
make test        # Run tests
make test-race   # With race detector
make cover       # Coverage report
make lint        # Static analysis
make bench       # Benchmarks
```

## Guidelines

- All tests must pass with `-race` flag
- Use `t.Parallel()` in tests that don't share state
- Provider interface changes require discussion first
- Add tests for new functionality
- Follow existing patterns (functional options, internal packages)

## Pull Requests

1. Open an issue first for significant changes
2. Run `make all` before submitting (vet + test + build)
3. Include test coverage for new code
4. Update CHANGELOG.md
