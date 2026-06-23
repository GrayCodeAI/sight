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
- Import `hawk-core-contracts/types` for cross-repo types

## Common Pitfalls

- Do not add LLM client implementations — that's the consumer's job
- The Provider interface is the boundary; keep it minimal
- Taint analysis tests need careful setup — see existing test patterns

## Naming Conventions

- **Types are nouns, not abbreviations**: `Finding`, `InlineComment`, `Result`, `Stats` — not `Fnd` or `InlCmt`
- **Option functions use `With` prefix**: `WithProvider()`, `WithMaxTokens()`, `WithParallel()` — never bare `Provider()`
- **Preset options are bare vars**: `Quick`, `Thorough`, `SecurityFocus`, `CI` — exported `var Option` values
- **Internal types mirror public ones**: public `Finding` maps to internal `review.Finding` via `toPublicFindings()`
- **Severity is a type alias**: `type Severity = types.Severity` from `hawk-core-contracts/types` — never define your own
- **Error sentinel naming**: `ErrNoProvider`, `ErrEmptyDiff`, `ErrContextCancelled` — always `Err` prefix, package-scoped
- **Mock types in tests**: `mockProvider` (unexported), implements `Provider` with `response string` and `err error` fields

## API Patterns

- **Functional options pattern**: all configuration goes through `Option` interface with `optFunc` adapter:
  ```go
  type Option interface { apply(*config) }
  type optFunc func(*config)
  func (f optFunc) apply(c *config) { f(c) }
  ```
- **One-shot + reusable**: `Review(ctx, diff, opts...)` creates a `Reviewer` internally; `NewReviewer(opts...)` for reuse
- **Sentinel errors**: returned directly (e.g. `ErrNoProvider`), not wrapped — callers compare with `==`
- **Result methods**: `Failed()` checks severity threshold, `MaxSeverity()` returns highest finding severity
- **JSON tags on all public struct fields**: `json:"concern"`, `json:"severity"`, etc. — `omitempty` for optional fields
- **Provider interface is minimal**: single `Chat(ctx, messages, opts) (*Response, error)` method — no streaming, no tools
- **Concurrency**: `Reviewer` is safe for concurrent use; internal `sync.Mutex` protects shared state during parallel reviews

## Testing Patterns

- **External test package**: `package sight_test` — tests import `sight` as a consumer would
- **Mock provider**: `mockProvider` struct with `response string`, `err error`, `calls int64` (mutex-protected counter)
- **Mock findings helper**: `mockFindings()` returns a JSON string matching the expected LLM response format
- **Test diff constant**: `testDiff` is a `const` unified diff used across multiple tests
- **Error path tests**: `TestReview_NoProvider`, `TestReview_EmptyDiff`, `TestReview_ProviderError` — each error sentinel gets its own test
- **Dedup test**: verify that identical findings from multiple concerns are collapsed to one
- **No table-driven tests for Review**: the function has too many options; individual test functions per scenario are preferred
- **Assertions use `t.Fatalf` for setup failures, `t.Errorf` for assertion failures** — never `t.Fatal` after assertions

## Refactoring Guidelines

- **Safe to refactor**: `dedup()`, `filterFiles()`, `matchesExclude()`, `countHunks()` — pure functions, well-tested
- **Safe to refactor**: `toPublicFindings()`, `toPublicComments()` — mapping functions, add fields freely
- **Do not touch**: `Provider` interface signature — breaking change for all consumers (hawk, eyrie integration)
- **Do not touch**: `Finding`, `Result`, `Stats` struct field names/tags — used in JSON serialization by consumers
- **Do not touch**: `Severity` type alias — it re-exports from `hawk-core-contracts/types`; changing it breaks cross-repo compatibility
- **Safe to extend**: add new `Option` functions, new presets, new `StaticRule` entries, new taint source/sink patterns
- **When adding concerns**: add to `defaultConfig().concerns` list and create corresponding `review.Concern` in `internal/review/`

## Key File Locations

| What | Where |
|---|---|
| Public API entry point | `sight.go` (types, `Review()`, error sentinels) |
| Reviewer implementation | `reviewer.go` (orchestration, parallel concerns, reflection) |
| Configuration & presets | `options.go` (`config` struct, `With*` functions, presets) |
| LLM provider interface | `provider.go` (`Provider`, `Message`, `ChatOpts`, `Response`) |
| Severity type alias | `severity.go` (re-exports from `hawk-core-contracts/types`) |
| Static analysis rules | `static_rules.go` (`StaticRule`, `StaticAnalyzer`, 30+ rules) |
| Taint analysis | `taint_analysis.go` (`TaintAnalyzer`, source/sink/sanitizer patterns) |
| Diff parsing internals | `internal/diff/` |
| Review concern building | `internal/review/` (concerns, prompts, response parsing) |
| Inline comment mapping | `internal/comment/` |
| Output formatters | `internal/output/` (SARIF, terminal) |
| Git context enrichment | `internal/context/` |
| Main test file | `sight_test.go` (mock provider, test diff, core scenarios) |
| Taint analysis tests | `taint_analysis_test.go` |
| Static rules tests | `static_rules_test.go` |
| SARIF output tests | `sarif_test.go` |
| Linter config | `.golangci.yml` (govet, ineffassign, nilerr, misspell) |
