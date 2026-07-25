// Package qualitygraph projects Sight review results into the portable
// hawk-eco graph contract without retaining source or review content.
package qualitygraph

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	graphcontracts "github.com/GrayCodeAI/hawk-core-contracts/graph"
	"github.com/GrayCodeAI/sight"
)

const (
	SchemaVersion = "sight.graph/v1"
	maxFindings   = 1000
)

type Export struct {
	SchemaVersion string                 `json:"schema_version"`
	GeneratedAt   time.Time              `json:"generated_at"`
	Scope         graphcontracts.Scope   `json:"scope,omitempty"`
	Nodes         []graphcontracts.Node  `json:"nodes"`
	Edges         []graphcontracts.Edge  `json:"edges"`
	Events        []graphcontracts.Event `json:"events"`
}

type Options struct {
	ObservedAt      time.Time
	Scope           graphcontracts.Scope
	CorrelationID   string
	ProducerVersion string
	Source          string
	MaxFindings     int
}

// Build creates a bounded, deterministic projection when ObservedAt is fixed.
func Build(result *sight.Result, opts Options) (*Export, error) {
	if result == nil {
		return nil, errors.New("qualitygraph: result is required")
	}
	observedAt := opts.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	limit := opts.MaxFindings
	if limit <= 0 || limit > maxFindings {
		limit = maxFindings
	}
	selected := result.Findings
	if len(selected) > limit {
		selected = selected[:limit]
	}
	sourceDigest := digest(opts.Source)
	resultDigest := digest(sourceDigest, observedAt.Format(time.RFC3339Nano))
	resultRef := graphcontracts.Ref{Kind: graphcontracts.NodeQuality, ID: "sight/review/" + resultDigest}
	provenance := graphcontracts.Provenance{
		Producer: "sight",
		Version:  strings.TrimSpace(opts.ProducerVersion),
		SourceID: resultDigest,
		Evidence: []graphcontracts.ArtifactRef{{URI: "sight://review/" + resultDigest}},
	}
	export := &Export{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   observedAt,
		Scope:         opts.Scope,
		Nodes:         make([]graphcontracts.Node, 0, len(selected)+1),
		Edges:         make([]graphcontracts.Edge, 0, len(selected)),
		Events:        make([]graphcontracts.Event, 0, len(selected)+1),
	}
	resultNode := graphcontracts.Node{
		ID: resultRef.ID, Kind: resultRef.Kind, Scope: opts.Scope,
		CreatedAt: observedAt, Provenance: provenance,
		Attributes: map[string]string{
			"entity":                "report",
			"status":                status(result),
			"max_severity":          result.MaxSeverity().String(),
			"fail_on":               result.FailOn.String(),
			"files_reviewed":        strconv.Itoa(result.Stats.FilesReviewed),
			"hunks_analyzed":        strconv.Itoa(result.Stats.HunksAnalyzed),
			"findings_total":        strconv.Itoa(result.Stats.FindingsTotal),
			"projected_findings":    strconv.Itoa(len(selected)),
			"truncated":             strconv.FormatBool(len(result.Findings) > len(selected)),
			"tokens_used":           strconv.Itoa(result.Stats.TokensUsed),
			"average_confidence":    strconv.FormatFloat(result.Stats.AverageConfidence, 'f', -1, 64),
			"high_confidence_count": strconv.Itoa(result.Stats.HighConfidenceCount),
			"low_confidence_count":  strconv.Itoa(result.Stats.LowConfidenceCount),
			"source_digest":         sourceDigest,
			"report_digest":         digest(result.Report),
		},
	}
	if err := resultNode.Validate(); err != nil {
		return nil, fmt.Errorf("qualitygraph: review node: %w", err)
	}
	export.Nodes = append(export.Nodes, resultNode)
	export.Events = append(export.Events, observed(resultRef, opts, observedAt, provenance))

	for index, finding := range selected {
		findingDigest := digest(
			resultRef.ID, strconv.Itoa(index), finding.Concern, finding.Severity.String(),
			finding.File, strconv.Itoa(finding.Line), strconv.Itoa(finding.EndLine),
			finding.Message, finding.Fix, finding.Reasoning, finding.CWE,
		)
		ref := graphcontracts.Ref{Kind: graphcontracts.NodeQuality, ID: "sight/finding/" + findingDigest}
		findingProvenance := graphcontracts.Provenance{
			Producer: "sight", Version: strings.TrimSpace(opts.ProducerVersion),
			SourceID: findingDigest,
			Evidence: []graphcontracts.ArtifactRef{{URI: "sight://finding/" + findingDigest}},
		}
		node := graphcontracts.Node{
			ID: ref.ID, Kind: ref.Kind, Scope: opts.Scope,
			CreatedAt: observedAt, Provenance: findingProvenance,
			Attributes: map[string]string{
				"entity":           "finding",
				"concern":          strings.TrimSpace(finding.Concern),
				"severity":         finding.Severity.String(),
				"line":             strconv.Itoa(finding.Line),
				"end_line":         strconv.Itoa(finding.EndLine),
				"confidence":       strconv.FormatFloat(finding.Confidence, 'f', -1, 64),
				"cwe":              strings.TrimSpace(finding.CWE),
				"sast_source":      strconv.FormatBool(finding.SASTSource),
				"file_digest":      digest(finding.File),
				"message_digest":   digest(finding.Message),
				"fix_digest":       digest(finding.Fix),
				"reasoning_digest": digest(finding.Reasoning),
			},
		}
		if err := node.Validate(); err != nil {
			return nil, fmt.Errorf("qualitygraph: finding[%d] node: %w", index, err)
		}
		export.Nodes = append(export.Nodes, node)
		edge := graphcontracts.Edge{
			ID: "sight/contains/" + digest(resultRef.ID, ref.ID), Kind: graphcontracts.EdgeContains,
			From: resultRef, To: ref, Scope: opts.Scope, CreatedAt: observedAt,
			Provenance: graphcontracts.Provenance{
				Producer: "sight", Version: strings.TrimSpace(opts.ProducerVersion), SourceID: findingDigest,
			},
		}
		if err := edge.Validate(); err != nil {
			return nil, fmt.Errorf("qualitygraph: finding[%d] edge: %w", index, err)
		}
		export.Edges = append(export.Edges, edge)
		export.Events = append(export.Events, observed(ref, opts, observedAt, findingProvenance))
	}
	sort.Slice(export.Nodes, func(i, j int) bool { return export.Nodes[i].ID < export.Nodes[j].ID })
	sort.Slice(export.Edges, func(i, j int) bool { return export.Edges[i].ID < export.Edges[j].ID })
	sort.Slice(export.Events, func(i, j int) bool { return export.Events[i].ID < export.Events[j].ID })
	return export, nil
}

func observed(ref graphcontracts.Ref, opts Options, at time.Time, provenance graphcontracts.Provenance) graphcontracts.Event {
	return graphcontracts.Event{
		ID:   "sight/observed/" + digest(ref.ID, at.Format(time.RFC3339Nano)),
		Type: graphcontracts.EventObserved, Subject: ref, Scope: opts.Scope, OccurredAt: at,
		CorrelationID:  strings.TrimSpace(opts.CorrelationID),
		IdempotencyKey: digest(ref.ID, at.Format(time.RFC3339Nano)),
		Provenance:     provenance,
	}
}

func status(result *sight.Result) string {
	if result.Failed() {
		return "failed"
	}
	return "passed"
}

func digest(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(strconv.Itoa(len(part))))
		_, _ = hash.Write([]byte{':'})
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
