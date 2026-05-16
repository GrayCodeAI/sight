package sight

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

type FilterConfig struct {
	MinSeverity         Severity
	ConfidenceThreshold float64
	MaxParallel         int
	BatchSize           int
}

func DefaultFilterConfig() FilterConfig {
	return FilterConfig{
		MinSeverity:         SeverityMedium,
		ConfidenceThreshold: 0.6,
		MaxParallel:         5,
		BatchSize:           10,
	}
}

type FilterResult struct {
	Finding    Finding
	Confirmed  bool
	Confidence float64
	Reasoning  string
}

func FilterFindings(ctx context.Context, provider Provider, findings []Finding,
	fileContents map[string]string, config FilterConfig,
) ([]Finding, []FilterResult, error) {
	if provider == nil {
		return findings, nil, ErrNoProvider
	}

	var toFilter []Finding
	var passThrough []Finding

	for _, f := range findings {
		if f.Severity.AtLeast(config.MinSeverity) {
			toFilter = append(toFilter, f)
		} else {
			passThrough = append(passThrough, f)
		}
	}

	if len(toFilter) == 0 {
		return passThrough, nil, nil
	}

	results := make([]FilterResult, len(toFilter))
	sem := make(chan struct{}, config.MaxParallel)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, finding := range toFilter {
		wg.Add(1)
		go func(idx int, f Finding) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}

			result := validateFinding(ctx, provider, f, fileContents)
			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, finding)
	}

	wg.Wait()

	if ctx.Err() != nil {
		return findings, nil, ErrContextCancelled
	}

	var confirmed []Finding
	confirmed = append(confirmed, passThrough...)

	for _, r := range results {
		if r.Confirmed && r.Confidence >= config.ConfidenceThreshold {
			confirmed = append(confirmed, r.Finding)
		}
	}

	return confirmed, results, nil
}

func validateFinding(ctx context.Context, provider Provider, f Finding, fileContents map[string]string) FilterResult {
	codeContext := ""
	if content, ok := fileContents[f.File]; ok {
		lines := strings.Split(content, "\n")
		start := f.Line - 5
		if start < 0 {
			start = 0
		}
		end := f.Line + 5
		if end > len(lines) {
			end = len(lines)
		}
		codeContext = strings.Join(lines[start:end], "\n")
	}

	prompt := fmt.Sprintf(`Evaluate whether this code review finding is a real issue or a false positive.

Finding:
- Concern: %s
- Severity: %s
- File: %s, Line: %d
- Message: %s
- Suggested Fix: %s

Code context:
%s

Respond with:
CONFIRMED: yes/no
CONFIDENCE: 0.0-1.0
REASONING: brief explanation`, f.Concern, f.Severity, f.File, f.Line, f.Message, f.Fix, codeContext)

	msgs := []Message{{Role: "user", Content: prompt}}
	resp, err := provider.Chat(ctx, msgs, ChatOpts{MaxTokens: 500, Temperature: 0.1})
	if err != nil {
		return FilterResult{Finding: f, Confirmed: true, Confidence: 0.5, Reasoning: "validation failed, keeping finding"}
	}

	return parseFilterResponse(f, resp.Content)
}

func parseFilterResponse(f Finding, response string) FilterResult {
	lower := strings.ToLower(response)

	confirmed := true
	if strings.Contains(lower, "confirmed: no") || strings.Contains(lower, "false positive") {
		confirmed = false
	}

	confidence := 0.7
	if idx := strings.Index(lower, "confidence:"); idx >= 0 {
		rest := strings.TrimSpace(lower[idx+len("confidence:"):])
		var val float64
		if _, err := fmt.Sscanf(rest, "%f", &val); err == nil && val >= 0 && val <= 1 {
			confidence = val
		}
	}

	reasoning := ""
	if idx := strings.Index(lower, "reasoning:"); idx >= 0 {
		reasoning = strings.TrimSpace(response[idx+len("reasoning:"):])
		if nl := strings.IndexByte(reasoning, '\n'); nl > 0 {
			reasoning = reasoning[:nl]
		}
	}

	return FilterResult{
		Finding:    f,
		Confirmed:  confirmed,
		Confidence: confidence,
		Reasoning:  reasoning,
	}
}
