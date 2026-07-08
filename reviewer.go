package sight

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GrayCodeAI/sight/internal/comment"
	gitctx "github.com/GrayCodeAI/sight/internal/context"
	"github.com/GrayCodeAI/sight/internal/diff"
	"github.com/GrayCodeAI/sight/internal/graph"
	"github.com/GrayCodeAI/sight/internal/output"
	"github.com/GrayCodeAI/sight/internal/review"
)

// Reviewer is a reusable code reviewer. Create one with NewReviewer and call
// Review multiple times. It is safe for concurrent use.
type Reviewer struct {
	cfg   *config
	g     *graph.DependencyGraph
	audit bool
}

// NewReviewer creates a configured Reviewer.
func NewReviewer(opts ...Option) *Reviewer {
	cfg := buildConfig(opts)
	r := &Reviewer{cfg: cfg}

	// Enable graph if available
	if cfg.graphEnabled {
		r.g = graph.New()
	}

	// Enable audit if configured
	if cfg.auditMode != AuditModeNone {
		r.audit = true
	}

	return r
}

// Review parses the diff, builds context, and runs multi-concern analysis.
func (r *Reviewer) Review(ctx context.Context, rawDiff string) (*Result, error) {
	if ctx.Err() != nil {
		return nil, ErrContextCancelled
	}
	if r.cfg.provider == nil {
		return nil, ErrNoProvider
	}
	if rawDiff == "" {
		return nil, ErrEmptyDiff
	}

	files := diff.Parse(rawDiff)
	if len(files) == 0 {
		return &Result{Report: "No reviewable changes found."}, nil
	}

	// Normalize file paths
	for i := range files {
		files[i].Path = filepath.Clean(files[i].Path)
	}

	// Filter excluded files before sending to LLM
	if len(r.cfg.exclude) > 0 {
		files = filterFiles(files, r.cfg.exclude)
		if len(files) == 0 {
			return &Result{Report: "All changed files matched exclude patterns."}, nil
		}
	}

	// Gather git context if enabled
	var gitContextStr string
	if r.cfg.gitContext {
		var filePaths []string
		for _, f := range files {
			if f.Path != "" {
				filePaths = append(filePaths, f.Path)
			}
		}
		contexts := gitctx.Enrich(filePaths)
		gitContextStr = gitctx.FormatContext(contexts)
	}

	allFindings := make([]Finding, 0, 64)
	// sastFindings collects pre-analysis findings for SAST-LLM fusion.
	// These are marked with SASTSource=true and injected into the LLM prompt.
	var sastFindings []Finding

	// Run static analysis and taint analysis as a pre-pass when enabled.
	// These pattern-based checks run before the LLM review and include their
	// findings in the final results alongside LLM findings.
	if r.cfg.preAnalysis {
		// Run static analysis (pattern-based rules) on the diff
		staticAnalyzer := NewStaticAnalyzer()
		for _, f := range files {
			if f.Path == "" {
				continue
			}
			lang := DetectLanguage(f.Path)
			var addedLines []string
			for _, hunk := range f.Hunks {
				for _, line := range hunk.Lines {
					if line.Type == diff.LineAdded {
						addedLines = append(addedLines, line.Content)
					}
				}
			}
			if len(addedLines) > 0 {
				content := strings.Join(addedLines, "\n")
				staticFindings := staticAnalyzer.AnalyzeFileWithPath(content, lang, f.Path)
				// Compute confidence for each static finding based on its rule.
				for i := range staticFindings {
					rule := findMatchingRule(staticAnalyzer.Rules, staticFindings[i])
					staticFindings[i].Confidence = CalculateStaticConfidence(staticFindings[i], rule)
				}
				allFindings = append(allFindings, staticFindings...)
			}
		}

		// Run taint analysis (data-flow tracking) on Go files in the diff
		taintAnalyzer := NewTaintAnalyzer()
		taintFindings := taintAnalyzer.AnalyzeDiff(rawDiff)
		// Compute confidence for each taint finding.
		for i := range taintFindings {
			taintFindings[i].Confidence = CalculateTaintConfidence(
				extractTaintSource(taintFindings[i].Message),
				extractTaintSink(taintFindings[i].Message),
				nil, // sanitizers already filtered out; no additional info available
			)
		}
		allFindings = append(allFindings, taintFindings...)

		// Mark all pre-analysis findings as SAST-originated and collect
		// them for injection into the LLM prompt (SAST-LLM fusion).
		for i := len(allFindings) - 1; i >= 0; i-- {
			if !allFindings[i].SASTSource {
				allFindings[i].SASTSource = true
			}
		}
		// Copy the SAST findings collected so far for prompt injection.
		sastFindings = make([]Finding, len(allFindings))
		copy(sastFindings, allFindings)
	}

	concerns := review.BuildConcerns(r.cfg.concerns)
	// Append custom concerns loaded from .sight/checks/ markdown files
	if len(r.cfg.customConcerns) > 0 {
		concerns = append(concerns, r.cfg.customConcerns...)
	}

	var (
		mu         sync.Mutex
		tokensUsed int
		durations  = make(map[string]time.Duration)
		llmErrors  []string
	)

	// Token budget: estimate prompt size and chunk if needed
	maxPromptTokens := r.cfg.maxTokens * 4 // assume 4:1 input:output ratio

	runConcern := func(concern review.Concern) {
		start := time.Now()

		// Early exit if context is already cancelled.
		if ctx.Err() != nil {
			return
		}

		chunks := review.ChunkFiles(files, concern, r.cfg.contextLines, maxPromptTokens)

		var concernFindings []review.Finding
		var concernTokens int
		var concernErrors []string

		for _, chunk := range chunks {
			// Check context between chunks to avoid unnecessary LLM calls.
			if ctx.Err() != nil {
				concernErrors = append(concernErrors, fmt.Sprintf("[%s] context cancelled", concern.Name))
				break
			}

			prompt := review.BuildPromptEnhanced(concern, chunk, r.cfg.contextLines)
			// Inject SAST pre-analysis findings into the LLM prompt so the
			// LLM can validate or dismiss each static analysis finding.
			if len(sastFindings) > 0 {
				prompt = BuildFusedPrompt(prompt, sastFindings)
			}
			if gitContextStr != "" {
				prompt += gitContextStr
			}

			systemPrompt := review.SystemPrompt(concern)
			if r.cfg.projectRules != "" {
				systemPrompt += "\n\n## Project Rules\n\nThe following project-specific rules and coding standards MUST be respected:\n\n" + r.cfg.projectRules
			}

			resp, err := r.cfg.provider.Chat(ctx, []Message{
				{Role: "user", Content: prompt},
			}, ChatOpts{
				Model:       r.cfg.model,
				MaxTokens:   r.cfg.maxTokens,
				Temperature: 0.1,
				System:      systemPrompt,
			})
			if err != nil {
				concernErrors = append(concernErrors, fmt.Sprintf("[%s] %v", concern.Name, err))
				continue
			}

			parsed := review.ParseResponse(resp.Content, concern.Name)
			concernFindings = append(concernFindings, parsed...)
			concernTokens += resp.TokensUsed
		}

		mu.Lock()
		allFindings = append(allFindings, toPublicFindings(concernFindings)...)
		tokensUsed += concernTokens
		durations[concern.Name] = time.Since(start)
		llmErrors = append(llmErrors, concernErrors...)
		mu.Unlock()
	}

	if r.cfg.parallel && len(concerns) > 1 {
		var wg sync.WaitGroup
		for _, concern := range concerns {
			// Don't launch new goroutines if context is already cancelled.
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func(c review.Concern) {
				defer wg.Done()
				runConcern(c)
			}(concern)
		}
		wg.Wait()
	} else {
		for _, concern := range concerns {
			if ctx.Err() != nil {
				break
			}
			runConcern(concern)
		}
	}

	allFindings = dedup(allFindings)

	// Track SAST-LLM fusion outcomes: which SAST findings did the LLM confirm vs dismiss.
	var fusionResult *SASTFusionResult
	if len(sastFindings) > 0 {
		// Separate LLM findings (not from SAST) for comparison.
		var llmFindings []Finding
		for _, f := range allFindings {
			if !f.SASTSource {
				llmFindings = append(llmFindings, f)
			}
		}
		result := TrackSASTOutcome(sastFindings, llmFindings)
		fusionResult = &result
	}

	// Self-reflection pass: validate findings with a second LLM call
	if r.cfg.reflection && len(allFindings) > 0 && ctx.Err() == nil {
		allFindings = r.reflect(ctx, allFindings, rawDiff, &tokensUsed)
	}

	sort.Slice(allFindings, func(i, j int) bool {
		if allFindings[i].Severity != allFindings[j].Severity {
			return allFindings[i].Severity > allFindings[j].Severity
		}
		if allFindings[i].File != allFindings[j].File {
			return allFindings[i].File < allFindings[j].File
		}
		return allFindings[i].Line < allFindings[j].Line
	})

	commentInputs := make([]comment.FindingInput, len(allFindings))
	for i, f := range allFindings {
		commentInputs[i] = comment.FindingInput{
			Concern:   f.Concern,
			Severity:  int(f.Severity),
			File:      f.File,
			Line:      f.Line,
			EndLine:   f.EndLine,
			Message:   f.Message,
			Fix:       f.Fix,
			Reasoning: f.Reasoning,
		}
	}
	comments := comment.MapToInlineFiltered(commentInputs, files, r.cfg.filterMode)

	bySev := make(map[Severity]int)
	byConcern := make(map[string]int)
	for _, f := range allFindings {
		bySev[f.Severity]++
		byConcern[f.Concern]++
	}

	avgConf, highConfCount, lowConfCount := ComputeConfidenceStats(allFindings)
	breakdown := BuildConfidenceBreakdown(allFindings)

	result := &Result{
		Findings:            allFindings,
		Comments:            toPublicComments(comments),
		SASTFusion:          fusionResult,
		ConfidenceBreakdown: breakdown,
		Stats: Stats{
			FilesReviewed:       len(files),
			HunksAnalyzed:       countHunks(files),
			FindingsTotal:       len(allFindings),
			BySeverity:          bySev,
			ByConcern:           byConcern,
			TokensUsed:          tokensUsed,
			DurationPerConcern:  durations,
			AverageConfidence:   avgConf,
			HighConfidenceCount: highConfCount,
			LowConfidenceCount:  lowConfCount,
		},
		FailOn: r.cfg.failOn,
	}
	outputFindings := make([]output.Finding, len(allFindings))
	for i, f := range allFindings {
		outputFindings[i] = output.Finding{
			Concern:   f.Concern,
			Severity:  int(f.Severity),
			File:      f.File,
			Line:      f.Line,
			EndLine:   f.EndLine,
			Message:   f.Message,
			Fix:       f.Fix,
			Reasoning: f.Reasoning,
			CWE:       f.CWE,
		}
	}
	outputStats := output.Stats{
		FilesReviewed:      result.Stats.FilesReviewed,
		HunksAnalyzed:      result.Stats.HunksAnalyzed,
		FindingsTotal:      result.Stats.FindingsTotal,
		BySeverity:         make(map[int]int),
		ByConcern:          result.Stats.ByConcern,
		TokensUsed:         result.Stats.TokensUsed,
		DurationPerConcern: result.Stats.DurationPerConcern,
	}
	for sev, count := range bySev {
		outputStats.BySeverity[int(sev)] = count
	}
	result.Report = output.FormatTerminal(outputFindings, outputStats)

	// Include LLM errors in the report if any occurred
	if len(llmErrors) > 0 {
		result.Report += "\n\nLLM provider errors (" + fmt.Sprintf("%d", len(llmErrors)) + "):\n"
		for _, e := range llmErrors {
			result.Report += "  - " + e + "\n"
		}
	}

	return result, nil
}

// ReviewFiles reviews a set of file changes with explicit content.
func (r *Reviewer) ReviewFiles(ctx context.Context, files []FileChange) (*Result, error) {
	if r.cfg.provider == nil {
		return nil, ErrNoProvider
	}
	inputs := make([]diff.FileChangeInput, len(files))
	for i, f := range files {
		inputs[i] = diff.FileChangeInput{
			Path:    f.Path,
			OldPath: f.OldPath,
			Diff:    f.Diff,
			Content: f.Content,
		}
	}
	combined := diff.CombineFileChanges(inputs)
	return r.Review(ctx, combined)
}

func toPublicFindings(internal []review.Finding) []Finding {
	out := make([]Finding, len(internal))
	for i, f := range internal {
		// Prefer LLM-provided CWE; fall back to keyword-based MatchCWE.
		cwe := f.CWE
		if cwe == "" {
			cwe = review.MatchCWE(f.Message, f.Fix)
		}
		conf := f.Confidence
		if conf <= 0 || conf > 1.0 {
			conf = 0.6 // default for LLM findings
		}
		out[i] = Finding{
			Concern:    f.Concern,
			Severity:   f.Severity,
			File:       f.File,
			Line:       f.Line,
			EndLine:    f.EndLine,
			Message:    f.Message,
			Fix:        f.Fix,
			Reasoning:  f.Reasoning,
			CWE:        cwe,
			Confidence: conf,
		}
	}
	return out
}

func toPublicComments(internal []comment.Inline) []InlineComment {
	out := make([]InlineComment, len(internal))
	for i, c := range internal {
		out[i] = InlineComment{
			Path:       c.Path,
			StartLine:  c.StartLine,
			EndLine:    c.EndLine,
			Body:       c.Body,
			Suggestion: c.Suggestion,
		}
	}
	return out
}

func dedup(findings []Finding) []Finding {
	type key struct {
		file    string
		line    int
		concern string
		message string
	}
	seen := make(map[key]bool)
	var result []Finding
	for _, f := range findings {
		// Use file+line+concern+message for unique identification.
		// If two different concerns produce the exact same message for the same
		// location, keep only the first (higher severity wins due to sort order).
		k := key{file: f.File, line: f.Line, concern: f.Concern, message: f.Message}
		// Also check without concern for cross-concern dedup of identical findings
		kNoConcern := key{file: f.File, line: f.Line, message: f.Message}
		if seen[k] || seen[kNoConcern] {
			continue
		}
		seen[k] = true
		seen[kNoConcern] = true
		result = append(result, f)
	}
	return result
}

func countHunks(files []diff.File) int {
	total := 0
	for _, f := range files {
		total += len(f.Hunks)
	}
	return total
}

// filterFiles removes files whose paths match any of the exclude patterns.
// Patterns support exact basename matching and filepath.Match-style globs.
func filterFiles(files []diff.File, patterns []string) []diff.File {
	var result []diff.File
	for _, f := range files {
		if !matchesExclude(f.Path, patterns) {
			result = append(result, f)
		}
	}
	return result
}

// matchesExclude checks if a file path matches any exclusion pattern.
// It checks both the full path and the basename against each pattern.
func matchesExclude(path string, patterns []string) bool {
	base := filepath.Base(path)
	for _, pattern := range patterns {
		// Check if the pattern contains a path separator — if so, match
		// against the full path; otherwise match against the basename.
		if strings.Contains(pattern, "/") {
			if matched, _ := filepath.Match(pattern, path); matched {
				return true
			}
		} else {
			// Exact basename match
			if base == pattern {
				return true
			}
			// Glob match on basename
			if matched, _ := filepath.Match(pattern, base); matched {
				return true
			}
		}
	}
	return false
}

// findMatchingRule returns the StaticRule that produced a given finding,
// or a zero-value StaticRule if no match is found.
func findMatchingRule(rules []StaticRule, f Finding) StaticRule {
	for _, rule := range rules {
		// Match by rule ID embedded in the message.
		if f.Concern == "static:"+rule.Category &&
			strings.Contains(f.Message, rule.ID) {
			return rule
		}
	}
	return StaticRule{}
}

// extractTaintSource extracts the taint source description from a taint finding
// message. The message format is:
//
//	[TAINT-<type>] <type>: <source> -> <sink> via variable "<var>"
func extractTaintSource(msg string) string {
	// Find content after "] " and before " -> "
	idx := strings.Index(msg, "] ")
	if idx < 0 {
		return "unknown"
	}
	rest := msg[idx+2:]
	// Skip the sink type prefix: "type: "
	if colonIdx := strings.Index(rest, ": "); colonIdx >= 0 {
		rest = rest[colonIdx+2:]
	}
	if arrowIdx := strings.Index(rest, " -> "); arrowIdx >= 0 {
		return rest[:arrowIdx]
	}
	return "unknown"
}

// extractTaintSink extracts the sink description from a taint finding message.
func extractTaintSink(msg string) string {
	arrowIdx := strings.Index(msg, " -> ")
	if arrowIdx < 0 {
		return "unknown"
	}
	rest := msg[arrowIdx+4:]
	if viaIdx := strings.Index(rest, " via variable"); viaIdx >= 0 {
		return rest[:viaIdx]
	}
	return rest
}

// reflect runs the self-reflection pass to validate findings.
func (r *Reviewer) reflect(ctx context.Context, findings []Finding, rawDiff string, tokensUsed *int) []Finding {
	internalFindings := make([]review.Finding, len(findings))
	for i, f := range findings {
		internalFindings[i] = review.Finding{
			Concern:    f.Concern,
			Severity:   f.Severity,
			File:       f.File,
			Line:       f.Line,
			EndLine:    f.EndLine,
			Message:    f.Message,
			Fix:        f.Fix,
			Reasoning:  f.Reasoning,
			Confidence: f.Confidence,
		}
	}

	prompt := review.BuildReflectPrompt(internalFindings, rawDiff)

	resp, err := r.cfg.provider.Chat(ctx, []Message{
		{Role: "user", Content: prompt},
	}, ChatOpts{
		Model:       r.cfg.model,
		MaxTokens:   r.cfg.maxTokens,
		Temperature: 0.1,
		System:      review.ReflectSystemPrompt,
	})
	if err != nil {
		return findings
	}

	*tokensUsed += resp.TokensUsed

	reflections := review.ParseReflectResponse(resp.Content)
	if len(reflections) == 0 {
		return findings
	}

	validated := review.ApplyReflectionWithScore(internalFindings, reflections, r.cfg.minScore)
	return toPublicFindings(validated)
}
