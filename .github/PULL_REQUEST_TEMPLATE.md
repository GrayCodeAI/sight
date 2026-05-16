<!--
  Thanks for your contribution! Please fill out this template so reviewers can
  understand the change quickly. Anything that does not apply can be left in
  place; do not delete unanswered sections — write "n/a".
-->

## Summary

<!--
  One paragraph describing what this PR does and why. Link the related
  issue(s) with `Fixes #N` or `Refs #N` if applicable.
-->

## Changes

<!--
  Bullet list of what changed, grouped by area (review pipeline, static
  rules, SARIF output, MCP, config, eval, internal/...). Reviewers should
  be able to skim this and know what to look at first.
-->

-

## Review-quality impact

<!--
  Sight is a code-review tool. Any change to the review pipeline, prompts,
  filtering, deduplication, or static rules can shift the false-positive /
  false-negative balance.

  - Did you change `reviewer.go`, `multi_concern.go`, `filter.go`,
    `static_rules.go`, `convention_check.go`, or anything in
    `internal/review/`?
  - If yes: paste before/after numbers from `go test ./... -run TestEval`
    (or the equivalent eval-set run) and call out which findings changed
    category (precision, recall, dedup rate).
  - If no: write "n/a".
-->

## SARIF compatibility

<!--
  Did you change `sarif.go` or `internal/output/sarif.go`?

  - If yes: confirm the output still validates against the SARIF 2.1.0
    schema and call out any new fields, especially in `tool.driver`.
  - If no: write "n/a".
-->

## Testing

<!--
  Describe how you tested. Paste output of `make test` and `make lint`. If
  you added new tests, list them.
-->

```text
$ make test
...
$ make lint
...
```

## Checklist

- [ ] Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
      (`feat:`, `fix:`, `perf:`, `refactor:`, `docs:`, `test:`, etc.)
- [ ] `make build` passes
- [ ] `make lint` passes
- [ ] `make test-race` passes locally
- [ ] New or changed code has tests (table-driven where appropriate)
- [ ] Public APIs in `sight.go`, `reviewer.go`, etc. have godoc comments
- [ ] `CHANGELOG.md` updated under `## [Unreleased]` if user-visible
- [ ] No new false-positive class introduced in eval set
- [ ] SARIF output (if touched) validates against the 2.1.0 schema
- [ ] No secrets, tokens, or PII in fixtures (eval inputs use synthetic
      diffs only)
- [ ] No `Co-authored-by:` trailers (this is solo-developer work)
