// Package sight version metadata.
//
// The Version variable is sourced at compile time from the VERSION file at
// the repo root, which is the single source of truth used by release tooling
// (release-please, goreleaser), and CI.
package sight

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

// Version of the sight library. Do not edit this variable directly — bump
// the VERSION file at the repo root instead.
var Version = strings.TrimSpace(versionFile)
