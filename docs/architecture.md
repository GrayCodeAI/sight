<div align="center">

# 👁️ sight Architecture

**AI-Powered Code Review on Diffs**

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://go.dev/)
[![Protocol](https://img.shields.io/badge/Protocol-MCP-purple)]()

</div>

---

## 🎯 Overview

sight is an AI-powered code review library for Go. It parses unified diffs, enriches with **code context** and **git history**, and runs **parallel multi-concern reviews** through an LLM provider.

> 💡 No LLM client bundled — consumers inject their own via the `Provider` interface.

---

## 🧱 Components

```
sight/
├── api/openapi.yaml          📜 MCP tool surface reference
├── cmd/sight/main.go         🖥️ CLI entry (mcp, taint subcommands)
├── sight.go                  📤 Public API: Review(), Finding, Result, Stats
├── reviewer.go               🔄 Reviewer: parallel concern orchestration
├── options.go                ⚙️ config, With* functions, presets
├── provider.go               🔌 Provider interface (consumers implement)
├── severity.go               📊 Re-exports from hawk/shared/types
├── static_rules.go           🛡️ 30+ static analysis rules
├── taint_analysis.go         🔗 SSA-based taint tracking
├── sast_integration.go       🔒 SAST-LLM fusion
├── autofix.go                🔧 Fix suggestion pipeline
├── eval.go                   📊 Evaluation harness
├── mcp/                      🔌 MCP server (stdio + HTTP)
└── internal/
    ├── diff/                 📄 Unified diff parser
    ├── review/               🧠 Concerns, prompts, response parsing
    ├── comment/              💬 Inline comment formatting
    ├── context/              📖 Code context + git blame
    └── output/               📊 SARIF and terminal formatters
```

---

## 📤 Public API

```go
// 🚀 One-shot review
result, err := sight.Review(ctx, diffText,
    sight.WithProvider(myLLMProvider),
    sight.Thorough,
)

// 🔄 Reusable reviewer
reviewer := sight.NewReviewer(sight.WithProvider(myLLMProvider))
result, err := reviewer.Review(ctx, diffText)

// ❌ Check if any findings are above threshold
if result.Failed() {
    fmt.Printf("Review failed: %d findings\n", len(result.Findings))
}
```

---

## 🔌 Provider Interface

```go
type Provider interface {
    Chat(ctx context.Context, messages []Message, opts ChatOpts) (*Response, error)
}
```

> Consumers implement this with their LLM client (e.g., using eyrie). hawk wires eyrie as the provider via `internal/bridge/sight/bridge.go`.

---

## ⚡ Presets

| Preset | Concerns | Speed |
|--------|----------|:-----:|
| 🏃 `Quick` | security, correctness | Fast |
| 📊 `Standard` | security, correctness, style, docs | Medium |
| 🔬 `Thorough` | all concerns | Slow |
| 🔒 `SecurityFocus` | security, taint only | Fast |
| 🤖 `CI` | Standard, fail on High+ | Medium |

---

## 🔌 MCP Server

```bash
sight mcp                                    # 📡 stdio transport
sight mcp --transport http --addr :8080      # 🌐 HTTP transport
```

**Tools:** `sight_review` · `sight_describe` · `sight_improve` · `sight_taint`

---

## 🔎 Findings

| Field | Description |
|-------|-------------|
| `Concern` | Review category (security, style, etc.) |
| `Severity` | 🟢 Info · 🟡 Low · 🟠 Medium · 🔴 High · 🟥 Critical |
| `File` / `Line` | Location in the diff |
| `Message` | What was found and why |
| `Fix` | Suggested fix |
| `CWE` | CWE reference (security findings) |
| `Confidence` | 0.0–1.0 score |
| `InlineComment` | PR-ready inline comment |

---

## 🛡️ Static Rules + Taint Analysis

**30+ built-in rules** run without LLM overhead — hardcoded secret patterns, SQL injection sinks, unsafe deserialization, etc. Fused with LLM results.

**Taint analysis** (`sight taint --path .`) uses SSA-based cross-function tracking to detect source→sink data flows. Sources, sinks, and sanitizers are configurable.
