# sight

Code review and security analysis tool. Reviews diffs, generates findings, and suggests fixes.

## Build & Test
- go test ./... -count=1 — run all tests
- go test -run "TestFixPipeline|TestMemoryBridge|TestConfidence" -count=1 — new features

## Architecture
- Root package: sight — reviewer, findings, fix pipeline, memory bridge
- internal/review/ — review engine, concerns, response handling
- internal/diff/ — diff parsing
- internal/comment/ — inline comment generation
- mcp/ — MCP server integration

## Key Patterns
- Fix pipeline: pattern-matching rules for auto-remediation
- Confidence scoring (0.0-1.0) on every finding
- SAST-LLM fusion: feeds SAST findings into LLM prompts
- Memory bridge: yaad integration via MemorySource interface

## Recent Additions
- Numeric confidence scoring
- SAST-LLM fusion
- Fix suggestion pipeline (7 built-in rules)
- Memory bridge for yaad integration
