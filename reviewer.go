package sight

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/GrayCodeAI/sight/internal/comment"
	gitctx "github.com/GrayCodeAI/sight/internal/context"
	"github.com/GrayCodeAI/sight/internal/diff"
	"github.com/GrayCodeAI/sight/internal/output"
	"github.com/GrayCodeAI/sight/internal/review"
)

// Reviewer is a reusable code reviewer. Create one with NewReviewer and call
// Review multiple times. It is safe for concurrent use.
type Reviewer struct {
	cfg *config
	mu  sync.Mutex
}

// NewReviewer creates a configured Reviewer.
func NewReviewer(opts ...Option) *Reviewer {
	return &Reviewer{cfg: buildConfig(opts)}
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

	// Gather git context if enabled
	var gitContextStr string
	if r.cfg.gitContext {
		filePaths := make([]string, len(files))
		for i, f := range files {
			filePaths[i] = f.Path
		}
		contexts := gitctx.Enrich(filePaths)
		gitContextStr = gitctx.FormatContext(contexts)
	}

	concerns := review.BuildConcerns(r.cfg.concerns)

	var (
		mu          sync.Mutex
		allFindings []Finding
		tokensUsed  int
		durations   = make(map[string]time.Duration)
	)

	// Token budget: estimate prompt size and chunk if needed
	maxPromptTokens := r.cfg.maxTokens * 4 // assume 4:1 input:output ratio

	runConcern := func(concern review.Concern) {
		start := time.Now()

		chunks := review.ChunkFiles(files, concern, r.cfg.contextLines, maxPromptTokens)

		var concernFindings []review.Finding
		var concernTokens int

		for _, chunk := range chunks {
			prompt := review.BuildPrompt(concern, chunk, r.cfg.contextLines)
			if gitContextStr != "" {
				prompt += gitContextStr
			}

			resp, err := r.cfg.provider.Chat(ctx, []Message{
				{Role: "user", Content: prompt},
			}, ChatOpts{
				Model:       r.cfg.model,
				MaxTokens:   r.cfg.maxTokens,
				Temperature: 0.1,
				System:      review.SystemPrompt(concern),
			})

			if err != nil {
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
		mu.Unlock()
	}

	if r.cfg.parallel && len(concerns) > 1 {
		var wg sync.WaitGroup
		for _, concern := range concerns {
			wg.Add(1)
			go func(c review.Concern) {
				defer wg.Done()
				runConcern(c)
			}(concern)
		}
		wg.Wait()
	} else {
		for _, concern := range concerns {
			runConcern(concern)
		}
	}

	allFindings = dedup(allFindings)
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
	comments := comment.MapToInline(commentInputs, files)

	bySev := make(map[Severity]int)
	byConcern := make(map[string]int)
	for _, f := range allFindings {
		bySev[f.Severity]++
		byConcern[f.Concern]++
	}

	result := &Result{
		Findings: allFindings,
		Comments: toPublicComments(comments),
		Stats: Stats{
			FilesReviewed:      len(files),
			HunksAnalyzed:      countHunks(files),
			FindingsTotal:      len(allFindings),
			BySeverity:         bySev,
			ByConcern:          byConcern,
			TokensUsed:         tokensUsed,
			DurationPerConcern: durations,
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
		out[i] = Finding{
			Concern:   f.Concern,
			Severity:  Severity(f.Severity),
			File:      f.File,
			Line:      f.Line,
			EndLine:   f.EndLine,
			Message:   f.Message,
			Fix:       f.Fix,
			Reasoning: f.Reasoning,
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
		message string
	}
	seen := make(map[key]bool)
	var result []Finding
	for _, f := range findings {
		k := key{file: f.File, line: f.Line, message: f.Message}
		if seen[k] {
			continue
		}
		seen[k] = true
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
