package qualitygraph_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	graphcontracts "github.com/GrayCodeAI/hawk-core-contracts/graph"
	"github.com/GrayCodeAI/sight"
	"github.com/GrayCodeAI/sight/qualitygraph"
)

func TestBuildPrivacySafeDeterministicProjection(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	result := &sight.Result{
		Report: "private review report", FailOn: sight.SeverityMedium,
		Stats: sight.Stats{FilesReviewed: 2, FindingsTotal: 1, TokensUsed: 42},
		Findings: []sight.Finding{{
			Concern: "security", Severity: sight.SeverityHigh,
			File: "/private/repo/main.go", Line: 12, EndLine: 14,
			Message: "private message", Fix: "private fix", Reasoning: "private reasoning",
			CWE: "CWE-22", Confidence: .91, SASTSource: true,
		}},
	}
	opts := qualitygraph.Options{
		ObservedAt: at, Scope: graphcontracts.Scope{RepositoryID: "repo"},
		CorrelationID: "session-1", Source: "private source diff",
	}
	first, err := qualitygraph.Build(result, opts)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	second, err := qualitygraph.Build(result, opts)
	if err != nil {
		t.Fatalf("second Build() error = %v", err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("projection is not deterministic")
	}
	if len(first.Nodes) != 2 || len(first.Edges) != 1 || len(first.Events) != 2 {
		t.Fatalf("unexpected sizes: nodes=%d edges=%d events=%d", len(first.Nodes), len(first.Edges), len(first.Events))
	}
	for _, secret := range []string{
		result.Report, result.Findings[0].File, result.Findings[0].Message,
		result.Findings[0].Fix, result.Findings[0].Reasoning, opts.Source,
	} {
		if strings.Contains(string(firstJSON), secret) {
			t.Fatalf("projection leaked %q", secret)
		}
	}
	if first.Edges[0].Kind != graphcontracts.EdgeContains {
		t.Fatalf("edge kind = %q", first.Edges[0].Kind)
	}
}

func TestBuildRejectsNilResult(t *testing.T) {
	t.Parallel()
	if _, err := qualitygraph.Build(nil, qualitygraph.Options{}); err == nil {
		t.Fatal("expected nil result error")
	}
}
