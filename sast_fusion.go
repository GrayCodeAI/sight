package sight

import (
	"fmt"
	"strings"
)

// SASTFusion formats static analysis findings for injection into LLM prompts.
// This is the core of SAST-LLM fusion: feeding SAST results into the LLM
// so it can validate or dismiss each finding, reducing false positives.
type SASTFusion struct {
	// MaxFindings caps the number of SAST findings injected into the prompt.
	// Zero means no limit.
	MaxFindings int
	// MaxEvidenceLen truncates each evidence snippet to this many characters.
	// Zero uses a default of 200.
	MaxEvidenceLen int
}

// NewSASTFusion creates a SASTFusion with sensible defaults.
func NewSASTFusion() *SASTFusion {
	return &SASTFusion{
		MaxFindings:    50,
		MaxEvidenceLen: 200,
	}
}

// FormatSASTForPrompt creates a structured "Pre-analysis findings" section
// suitable for injection into an LLM prompt. Each finding is rendered with
// its rule, severity, file location, message, and evidence snippet.
func (sf *SASTFusion) FormatSASTForPrompt(findings []Finding) string {
	if len(findings) == 0 {
		return "## Pre-Analysis Findings (SAST)\n\nNo static analysis findings detected.\n"
	}

	limit := len(findings)
	if sf.MaxFindings > 0 && limit > sf.MaxFindings {
		limit = sf.MaxFindings
	}

	if sf.MaxEvidenceLen <= 0 {
		sf.MaxEvidenceLen = 200
	}

	var b strings.Builder
	b.WriteString("## Pre-Analysis Findings (SAST)\n\n")
	b.WriteString("The following static analysis findings were detected before your review. ")
	b.WriteString("For each finding, please:\n")
	b.WriteString("1. VALIDATE it if you confirm the issue is real and actionable.\n")
	b.WriteString("2. DISMISS it if it is a false positive or not actionable.\n")
	b.WriteString("If you validate a finding, include it in your response with the original finding's details. ")
	b.WriteString("If you dismiss it, include it in your response with action \"dismiss\" and explain why.\n\n")
	b.WriteString(fmt.Sprintf("Found %d potential issues:\n\n", len(findings)))

	for i := 0; i < limit; i++ {
		f := findings[i]
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		severity := f.Severity.String()
		if severity == "" || severity == "0" {
			severity = "unknown"
		}

		msg := f.Message
		if sf.MaxEvidenceLen > 0 && len(msg) > sf.MaxEvidenceLen {
			msg = msg[:sf.MaxEvidenceLen] + "..."
		}
		b.WriteString(fmt.Sprintf("- [%s] %s (%s)\n", severity, msg, f.Concern))
		b.WriteString(fmt.Sprintf("  Location: %s\n", loc))
		if f.Fix != "" {
			fix := f.Fix
			if sf.MaxEvidenceLen > 0 && len(fix) > sf.MaxEvidenceLen {
				fix = fix[:sf.MaxEvidenceLen] + "..."
			}
			b.WriteString(fmt.Sprintf("  Fix: %s\n", fix))
		}
		b.WriteString("\n")
	}

	if len(findings) > limit {
		b.WriteString(fmt.Sprintf("... and %d more findings omitted.\n\n", len(findings)-limit))
	}

	return b.String()
}

// BuildFusedPrompt injects SAST findings into the base review prompt.
// The SAST section is placed before the diff content so the LLM can factor
// the pre-analysis results into its review from the start.
func BuildFusedPrompt(basePrompt string, sastFindings []Finding) string {
	if len(sastFindings) == 0 {
		return basePrompt
	}

	fusion := NewSASTFusion()
	sastSection := fusion.FormatSASTForPrompt(sastFindings)

	// Inject the SAST section before the diff content marker.
	// If the prompt has a <diff_content> tag, insert before it; otherwise prepend.
	const diffMarker = "<diff_content>"
	if idx := strings.Index(basePrompt, diffMarker); idx != -1 {
		return basePrompt[:idx] + sastSection + "\n" + basePrompt[idx:]
	}
	return sastSection + "\n" + basePrompt
}

// SASTFusionResult tracks how the LLM handled SAST findings.
type SASTFusionResult struct {
	// Confirmed lists SAST findings the LLM validated as real issues.
	Confirmed []Finding
	// Dismissed lists SAST findings the LLM considered false positives.
	Dismissed []Finding
	// Unaddressed lists SAST findings the LLM did not mention (implicitly dismissed).
	Unaddressed []Finding
}

// TrackSASTOutcome compares SAST findings fed into the prompt against the
// LLM's final findings to determine which were confirmed vs dismissed.
// A SAST finding is considered confirmed if the LLM's findings contain a
// finding at the same file and line with a similar message. Otherwise it
// is considered dismissed.
func TrackSASTOutcome(sastFindings []Finding, llmFindings []Finding) SASTFusionResult {
	var result SASTFusionResult

	for _, sf := range sastFindings {
		confirmed := false
		for _, lf := range llmFindings {
			if lf.File == sf.File && lf.Line == sf.Line && messageOverlap(sf.Message, lf.Message) {
				confirmed = true
				break
			}
		}
		if confirmed {
			result.Confirmed = append(result.Confirmed, sf)
		} else {
			result.Dismissed = append(result.Dismissed, sf)
		}
	}

	// Find LLM findings at SAST locations that didn't match by message
	// (new findings at the same spot) -- these are unaddressed from the
	// SAST perspective but we still track them.
	for _, lf := range llmFindings {
		if lf.SASTSource {
			continue
		}
		for _, sf := range sastFindings {
			if lf.File == sf.File && lf.Line == sf.Line && !messageOverlap(sf.Message, lf.Message) {
				result.Unaddressed = append(result.Unaddressed, lf)
				break
			}
		}
	}

	return result
}

// messageOverlap returns true if two messages share enough keywords to
// likely refer to the same issue. This is a simple heuristic based on
// shared significant words.
func messageOverlap(a, b string) bool {
	aWords := extractSignificantWords(strings.ToLower(a))
	bWords := extractSignificantWords(strings.ToLower(b))
	if len(aWords) == 0 || len(bWords) == 0 {
		return false
	}

	// Count shared words
	shared := 0
	bSet := make(map[string]bool, len(bWords))
	for _, w := range bWords {
		bSet[w] = true
	}
	for _, w := range aWords {
		if bSet[w] {
			shared++
		}
	}

	// Require at least 40% overlap relative to the shorter message
	minLen := len(aWords)
	if len(bWords) < minLen {
		minLen = len(bWords)
	}
	threshold := float64(minLen) * 0.4
	return float64(shared) >= threshold
}

// extractSignificantWords splits text into words and filters out common
// stop words and very short tokens.
func extractSignificantWords(text string) []string {
	stopWords := map[string]bool{
		"a": true, "an": true, "the": true, "in": true, "on": true,
		"at": true, "to": true, "for": true, "of": true, "with": true,
		"by": true, "is": true, "are": true, "was": true, "were": true,
		"be": true, "been": true, "has": true, "have": true, "had": true,
		"do": true, "does": true, "did": true, "will": true, "would": true,
		"could": true, "should": true, "may": true, "might": true, "can": true,
		"and": true, "or": true, "but": true, "not": true, "no": true,
		"if": true, "then": true, "than": true, "that": true, "this": true,
		"it": true, "its": true, "from": true, "into": true, "up": true,
		"out": true, "so": true, "as": true, "via": true,
	}

	words := strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == ',' || r == '.' || r == ':' || r == ';' ||
			r == '(' || r == ')' || r == '[' || r == ']' || r == '"' ||
			r == '\'' || r == '-' || r == '_' || r == '/' || r == '\\'
	})

	var significant []string
	for _, w := range words {
		w = strings.TrimSpace(w)
		if len(w) >= 3 && !stopWords[w] {
			significant = append(significant, w)
		}
	}
	return significant
}
