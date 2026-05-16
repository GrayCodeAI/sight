// Package sight version metadata.
//
// The Version variable is sourced at compile time from the VERSION file at
// the repo root, which is the single source of truth used by release tooling
// (release-please, goreleaser), CI, and the SARIF tool driver field.
package sight

import (
	_ "embed"
	"strings"

	"github.com/GrayCodeAI/sight/internal/output"
)

//go:embed VERSION
var versionFile string

// Version of the sight library. Do not edit this variable directly — bump
// the VERSION file at the repo root instead.
var Version = strings.TrimSpace(versionFile)

func init() {
	// Propagate canonical version into the internal/output package so the
	// SARIF tool driver field reflects the real version without duplicating
	// the constant across files.
	output.SetToolVersion(Version)
}
