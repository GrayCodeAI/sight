<p align="center">
  <h1 align="center">Sight</h1>
  <p align="center">
    <strong>AI-powered code review for diffs</strong>
  </p>
  <p align="center">
    <a href="https://golang.org/"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
    <a href="https://github.com/GrayCodeAI/sight/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/GrayCodeAI/sight/ci.yml?style=flat-square&label=tests" alt="CI"></a>
  </p>
</p>

---

Sight provides intelligent code review capabilities by analyzing diffs with AI. It understands context, identifies issues, and suggests improvements.

## Product boundary

Sight reviews source changes, diffs, dependency structure, and static-analysis
results. It does not crawl or audit a running website. Browser or deployed-URL
auditing belongs to `inspect`; Hawk is responsible for composing results when a
workflow needs both source review and live-target verification.

## Ecosystem Boundaries

Sight is a Hawk support engine. Keep the dependency edge one-way:

- use `hawk-core-contracts` for any cross-repo shared contracts (severity/finding vocabulary)
- do not import `hawk/internal/*`
- do not import removed legacy path `hawk/shared/types`; use `hawk-core-contracts/types`
- do not import other engines (`eyrie`, `yaad`, `tok`, `trace`, `inspect`) — engines are peers, not dependencies

> **Note:** `memory_bridge.go` is an intentional boundary exception — it calls
> `yaad` directly for automated memory persistence after reviews. This is documented
> as a known trade-off; the canonical integration path is via hawk.

## Features

- **Diff-aware analysis** - Reviews only changed code with full context
- **Severity classification** - Categorizes findings by impact
- **Provider agnostic** - Works with any LLM provider through the `Provider` interface
- **Extensible rules** - Add custom review rules for your codebase

## Quick Start

```bash
go get github.com/GrayCodeAI/sight
```

```go
import "github.com/GrayCodeAI/sight"

reviewer := sight.NewReviewer(
    sight.WithProvider(myLLMProvider),
    sight.Thorough,
)

result, err := reviewer.Review(ctx, diff)
for _, f := range result.Findings {
    fmt.Printf("[%s] %s:%d - %s\n", f.Severity, f.File, f.Line, f.Message)
}
```

## Examples

See the [examples/](examples/) directory for runnable code samples.

## Provider Interface

Implement the `Provider` interface to use any LLM:

```go
type Provider interface {
    Chat(ctx context.Context, messages []Message, opts ChatOpts) (*Response, error)
}
```

## Installation

```bash
go get github.com/GrayCodeAI/sight@latest
```

Requires Go 1.26+.

## Contributing

Contributions are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

MIT - see [LICENSE](LICENSE) for details.
