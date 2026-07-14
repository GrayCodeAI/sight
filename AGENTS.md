---
description: sight — diff-based code review build and test conventions.
globs: "*.go"
alwaysApply: false
---

# sight Conventions

AI-powered code review for diffs.

## Development workflow

When starting any new work (feature, fix, refactor, chore), always create a feature branch from `main` first. Never commit directly to `main`. Use branch naming conventions like `feat/<description>`, `fix/<description>`, or `chore/<description>`. Open a PR, ensure CI is green, then merge.

## Build & Test

```bash
go build ./...                    # Build library
go test ./...                     # Run tests
go test -race ./...               # Race detector
go vet ./...                      # Static analysis
```

## Architecture

- Reviews source changes, diffs, dependency structure, and static-analysis results
- Does not crawl or audit running websites (that belongs to `inspect`)
- Provider interface: `type Provider interface { Chat(ctx, messages, opts) }`

## Ecosystem Boundaries

- Use `hawk-core-contracts` for cross-repo shared types
- Do not import `hawk/internal/*` or legacy `hawk/shared/types`
- Do not import other engines (`eyrie`, `yaad`, `tok`, `trace`, `inspect`)

For full hawk-eco extension guidelines, see [hawk/AGENTS.md](https://github.com/GrayCodeAI/hawk/blob/main/AGENTS.md).
