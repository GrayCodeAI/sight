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
├── examples/basic/main.go    🧪 Library usage example (Review with a mock provider)
├── sight.go                  📤 Public API: Review(), Finding, Result, Stats
├── reviewer.go               🔄 Reviewer: parallel concern orchestration
├── options.go                ⚙️ config, With* functions, presets
├── provider.go               🔌 Provider interface (consumers implement)
├── severity.go               📊 Re-exports from hawk-core-contracts/types
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

sight ships no standalone binary — the MCP server is an embeddable component
that the host program (e.g. `hawk`) starts after injecting a `Provider`:

```go
srv := mcp.New(myProvider, sight.Thorough)
srv.ServeStdio()             // 📡 stdio transport
srv.ServeHTTP("127.0.0.1:8080") // 🌐 streamable HTTP transport, served at /mcp
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

**Taint analysis** (exposed via the `sight_taint` MCP tool and the taint-analysis API) uses SSA-based cross-function tracking to detect source→sink data flows. Sources, sinks, and sanitizers are configurable.

---

## 🔗 Structural Dependency Graph

The `internal/graph` package provides **optional structural dependency analysis** for code reviews:

**Key capabilities:**
- Parse Go AST to build structural dependency graph
- Blast-radius analysis: identify all files affected by changes
- Transitive dependency tracking
- Impact scoring based on depth and number of dependents
- SQLite persistence for incremental updates

**Usage:**
```go
// Enable graph-backed review
g := graph.New()
// ... build graph or load from SQLite ...

// Run blast radius analysis
result := g.GetBlastRadius([]string{"file.go"})
fmt.Printf("Direct: %d, Transitive: %d\n", result.Direct, result.Transitive)
```

**Tools exposed via MCP:** `sight_graph_blastRadius`, `sight_graph_query`, `sight_graph_stats`

---

## 🔒 Security Auditing

The `internal/audit` package provides **agent surface security auditing**:

**Key capabilities:**
- Concurrent security scanning of multiple targets
- Filter findings by severity (critical, high, medium, low) or category
- Integration with MCP hooks, permissions, and endpoints
- Webhook validation and test requests
- JSON-serializable audit findings

**Usage:**
```go
// Create audit scope
auditScope := &audit.AuditScope{
    Targets: []audit.AuditTarget{
        {Type: audit.AuditTargetHooks, Path: "/hooks/webhook"},
        {Type: audit.AuditTargetEndpoints, Path: "/api/endpoint"},
    },
    Rules: []string{"detect_unauthenticated_endpoints", "detect_hardcoded_secrets"},
}

// Run audit
report, err := audit.Audit(ctx, auditScope)
if report.Count() > 0 {
    fmt.Printf("Found %d security issues\n", report.Count())
}
```

---

## 🌐 Browser Automation Tools

The `internal/tool` package provides **HTTP-based browser automation** capabilities:

**Key capabilities:**
- HTTP client with configurable timeouts and redirects
- Browser tool with GET, POST, and header management
- Response parsing with JSON support
- Webhook testing: send test payloads and validate responses
- Formatter for structured output

**Usage:**
```go
// Create browser tool
browser := tool.NewBrowserTool()

// Make requests
resp, err := browser.Get(ctx, "https://example.com")
if err == nil && resp.IsSuccess() {
    fmt.Printf("Status: %d\n", resp.StatusCode)
}

// Test webhooks
webhook := tool.NewWebhookTester()
resp, err := webhook.SendTestRequest(ctx, "https://webhook.example.com", payload)
```
