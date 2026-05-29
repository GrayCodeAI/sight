# AGENTS.md — Sight

AI-powered code review library for diffs. Parses unified diffs, enriches with code context and git history, runs parallel multi-concern reviews through an LLM provider.

## Design Principles

- **Library only** — no CLI, no binary
- **No LLM SDK dependency** — defines a Provider interface; consumers implement it
- **No opinions** — consumers inject their own LLM client (e.g., via eyrie)

## Build & Test

```bash
go test ./...                    # Run all tests
go test -race ./...              # Race detector
go test -coverprofile=c.out ./... # Coverage
go vet ./...                     # Static analysis
gofumpt -w .                     # Format
```

## Architecture

- `diff_parser.go` — Parses unified diffs into structured hunks
- `enricher.go` — Adds surrounding code context and git blame
- `reviewer.go` — Runs multi-concern parallel reviews
- `provider.go` — LLM provider interface (consumers implement this)
- `finding.go` — Review findings with severity and suggestions
- `taint_analysis.go` — Security taint tracking for vulnerability detection
- `internal/output/` — SARIF and other output formatters

## Conventions

- Go 1.26+, pure Go, no CGO
- Table-driven tests
- Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`
- No `Co-authored-by:` trailers (auto-stripped by githook)
- `gofumpt` formatting enforced in CI
- Import `shared/types` from hawk for cross-repo types

## Common Pitfalls

- Do not add LLM client implementations — that's the consumer's job
- The Provider interface is the boundary; keep it minimal
- Taint analysis tests need careful setup — see existing test patterns
