# Changelog

All notable changes to sight are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0](https://github.com/GrayCodeAI/sight/compare/v0.2.0...v0.3.0) (2026-05-18)


### Features

* add severity levels and update review concerns ([0fbe668](https://github.com/GrayCodeAI/sight/commit/0fbe6688a5bada3621448e1001ca94ee3f290077))


### Bug Fixes

* add local hawk replace for shared/types dependency ([1131ddb](https://github.com/GrayCodeAI/sight/commit/1131ddb81af2bdea140734aa1c1180f26dc2aea4))
* clone hawk in CI for shared/types dependency ([2032cbb](https://github.com/GrayCodeAI/sight/commit/2032cbb7d15e72f5cacd12af93c2c97ebdf9ca4e))
* gofumpt formatting + go mod tidy ([c54eb6b](https://github.com/GrayCodeAI/sight/commit/c54eb6b075820ee43b826c43031029e43ce086aa))
* remove sarif replace directive, use v0.2.0 ([c167b02](https://github.com/GrayCodeAI/sight/commit/c167b020e9e9dcabb7fc71171c67a42940dff3d5))
* repair malformed CI workflow YAML ([7811d47](https://github.com/GrayCodeAI/sight/commit/7811d474096869ccef14cb8a8c8fdffafd40190e))
* update go.sum for sarif v0.2.0 ([f1c7f98](https://github.com/GrayCodeAI/sight/commit/f1c7f9830f450dbe99618c887d8bf7e1c3eb9391))
* upgrade Go from 1.26.1 to 1.26.3 to patch stdlib vulnerabilities ([4ff0593](https://github.com/GrayCodeAI/sight/commit/4ff0593cfda16ca0e29648f8cad824c093e47474))


### Refactoring

* remove sarif dependency and simplify version ([d4b65a5](https://github.com/GrayCodeAI/sight/commit/d4b65a50fc2705860e9a260fb62a9331c30def08))

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
  config / eval / output) and solo-dev fit checks.
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
