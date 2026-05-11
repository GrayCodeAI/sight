# Changelog

All notable changes to sight are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

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
