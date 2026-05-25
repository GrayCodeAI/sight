# Changelog

All notable changes to sight are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Changed
- **Version re-baselined to `0.2.0`** across the MCP server advertisement
  and both SARIF driver-version sites. Aligns sight with the rest of
  the hawk-eco ecosystem (`hawk`, `tok`, `eyrie`, `yaad`, `trace`,
  `inspect`).
  - `mcp/server.go`: `mcpserver.NewMCPServer("sight", "0.2.0", ...)`
  - `sarif.go`: `Driver.Version`/`Driver.SemanticVersion` → `"0.2.0"`
    (the SARIF spec version remains `"2.1.0"` — that's a different
    field; it identifies the SARIF format, not the tool)
  - `internal/output/sarif.go`: same fix in the duplicated SARIF code

### Added — Production hygiene (top-50 OSS parity)
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1.
- `.gitattributes` — LF normalization, binary detection, GitHub
  linguist hints (collapse `go.sum` in PR diffs).
- `.editorconfig` — UTF-8, LF, final newline, trim trailing whitespace,
  tabs for Go, 2-space indent for YAML/JSON/TOML.
- `.github/dependabot.yml` — weekly `gomod` and `github-actions`
  updates.
- `.github/PULL_REQUEST_TEMPLATE.md` — Summary / Changes / Review-
  quality impact (eval-set numbers) / Testing / Checklist.
- `.github/ISSUE_TEMPLATE/bug_report.yml` — structured bug report
  with surface dropdown (library API / MCP / SARIF output / eval).
- `.github/ISSUE_TEMPLATE/feature_request.yml` — feature request with
  a `kind` selector (review concerns / static rules / SARIF / MCP /
  config / eval / output) and developer fit checks.
- `.github/ISSUE_TEMPLATE/config.yml` — routes security to advisories,
  questions to discussions, blocks blank issues.

---

## [0.4.0] — 2026-05-08

### Added
- Multi-concern parallel review with configurable concern specs
- Self-reflection pass for false-positive elimination
- Incremental review with last-reviewed commit tracking
- Eval framework for review quality regression testing
- Custom checks via .sight/checks/ markdown files
- Project rules ingestion from CLAUDE.md, CONTRIBUTING.md, .cursor/rules/
- SARIF output format
- MCP server integration (sight_review, sight_describe, sight_improve)

### Changed
- Improved token budget estimation with 4:1 input:output ratio
- Finding deduplication across concerns

---

## [0.2.0] — 2026-04-30

### Added
- Describe operation (PR description generation)
- Improve operation (code improvement suggestions)
- Filter findings with LLM validation
- InlineComment mapping for GitHub/GitLab posting
- TOML/JSON configuration file support
- File exclusion patterns

---

## [0.1.0] — 2026-04-28

### Added
- Initial release: Review() function with Provider interface
- Finding type with severity, CWE, file/line location
- Functional options pattern for configuration
- Quick, Standard, Thorough presets
- Concurrent concern processing
