package sight

import reviewcontracts "github.com/GrayCodeAI/hawk-core-contracts/review"

// ToContractFinding converts a sight finding into the shared review contract.
func ToContractFinding(f Finding) reviewcontracts.Finding {
	return reviewcontracts.Finding{
		Concern:    f.Concern,
		Severity:   f.Severity,
		File:       f.File,
		Line:       f.Line,
		EndLine:    f.EndLine,
		Message:    f.Message,
		Fix:        f.Fix,
		Reasoning:  f.Reasoning,
		CWE:        f.CWE,
		Confidence: f.Confidence,
		SASTSource: f.SASTSource,
	}
}

// ToContractFindings converts sight findings into shared review contracts.
func ToContractFindings(findings []Finding) []reviewcontracts.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]reviewcontracts.Finding, len(findings))
	for i, f := range findings {
		out[i] = ToContractFinding(f)
	}
	return out
}

// FromContractFinding converts a shared review contract into a sight finding.
func FromContractFinding(f reviewcontracts.Finding) Finding {
	return Finding{
		Concern:    f.Concern,
		Severity:   f.Severity,
		File:       f.File,
		Line:       f.Line,
		EndLine:    f.EndLine,
		Message:    f.Message,
		Fix:        f.Fix,
		Reasoning:  f.Reasoning,
		CWE:        f.CWE,
		Confidence: f.Confidence,
		SASTSource: f.SASTSource,
	}
}

// ToContractInlineComment converts a sight inline comment into the shared review contract.
func ToContractInlineComment(c InlineComment) reviewcontracts.InlineComment {
	return reviewcontracts.InlineComment{
		Path:       c.Path,
		StartLine:  c.StartLine,
		EndLine:    c.EndLine,
		Body:       c.Body,
		Suggestion: c.Suggestion,
	}
}

// ToContractInlineComments converts sight inline comments into shared review contracts.
func ToContractInlineComments(comments []InlineComment) []reviewcontracts.InlineComment {
	if len(comments) == 0 {
		return nil
	}
	out := make([]reviewcontracts.InlineComment, len(comments))
	for i, c := range comments {
		out[i] = ToContractInlineComment(c)
	}
	return out
}

func toContractConfidenceBreakdown(b *ConfidenceBreakdown) *reviewcontracts.ConfidenceBreakdown {
	if b == nil {
		return nil
	}
	return &reviewcontracts.ConfidenceBreakdown{
		High:   ToContractFindings(b.High),
		Medium: ToContractFindings(b.Medium),
		Low:    ToContractFindings(b.Low),
	}
}

func toContractStats(s Stats) reviewcontracts.Stats {
	return reviewcontracts.Stats{
		FilesReviewed:       s.FilesReviewed,
		HunksAnalyzed:       s.HunksAnalyzed,
		FindingsTotal:       s.FindingsTotal,
		BySeverity:          s.BySeverity,
		ByConcern:           s.ByConcern,
		TokensUsed:          s.TokensUsed,
		DurationPerConcern:  s.DurationPerConcern,
		AverageConfidence:   s.AverageConfidence,
		HighConfidenceCount: s.HighConfidenceCount,
		LowConfidenceCount:  s.LowConfidenceCount,
	}
}

// ToContractResult converts a sight result into the shared review contract.
func ToContractResult(r *Result) *reviewcontracts.Result {
	if r == nil {
		return nil
	}
	return &reviewcontracts.Result{
		Findings:            ToContractFindings(r.Findings),
		Comments:            ToContractInlineComments(r.Comments),
		Stats:               toContractStats(r.Stats),
		Report:              r.Report,
		FailOn:              r.FailOn,
		ConfidenceBreakdown: toContractConfidenceBreakdown(r.ConfidenceBreakdown),
	}
}
