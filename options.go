package sight

import (
	"github.com/GrayCodeAI/sight/internal/comment"
	"github.com/GrayCodeAI/sight/internal/review"
)

// FilterMode re-exports the comment package's FilterMode for public use.
// It controls which lines are eligible for inline comment placement.
type FilterMode = comment.FilterMode

// Filter mode constants re-exported for public use.
const (
	FilterAdded       = comment.FilterAdded
	FilterDiffContext = comment.FilterDiffContext
	FilterFile        = comment.FilterFile
	FilterNone        = comment.FilterNone
)

// Option configures a review operation.
type Option interface {
	apply(*config)
}

type optFunc func(*config)

func (f optFunc) apply(c *config) { f(c) }

type config struct {
	provider       Provider
	model          string
	concerns       []string
	customConcerns []review.Concern
	maxTokens      int
	contextLines   int
	failOn         Severity
	filterMode     comment.FilterMode
	gitContext     bool
	symbols        bool
	parallel       bool
	reflection     bool
	preAnalysis    bool
	exclude        []string
	minScore       int
	projectRules   string
}

// defaultExclude is the default set of file patterns excluded from review.
// These are generated files, lock files, and minified assets that produce
// noise and waste tokens.
var defaultExclude = []string{
	"go.sum",
	"package-lock.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"*.min.js",
	"*.min.css",
	"*.map",
	"*.generated.*",
}

func defaultConfig() *config {
	return &config{
		concerns:     []string{"security", "bugs", "performance", "correctness", "style"},
		maxTokens:    4096,
		contextLines: 10,
		failOn:       SeverityCritical,
		gitContext:   true,
		symbols:      true,
		parallel:     true,
		exclude:      defaultExclude,
		minScore:     3,
	}
}

func buildConfig(opts []Option) *config {
	cfg := defaultConfig()
	for _, o := range opts {
		o.apply(cfg)
	}
	return cfg
}

// Presets

// Quick performs a fast single-pass review focusing on bugs and security only.
var Quick Option = optFunc(func(c *config) {
	c.concerns = []string{"security", "bugs"}
	c.contextLines = 5
	c.parallel = false
	c.gitContext = false
})

// Thorough performs a comprehensive multi-concern parallel review.
var Thorough Option = optFunc(func(c *config) {
	c.concerns = []string{"security", "bugs", "performance", "correctness", "style"}
	c.contextLines = 15
	c.parallel = true
	c.gitContext = true
	c.symbols = true
})

// SecurityFocus limits review to security concerns with deeper analysis.
var SecurityFocus Option = optFunc(func(c *config) {
	c.concerns = []string{"security"}
	c.contextLines = 20
	c.maxTokens = 8192
	c.gitContext = true
})

// CI configures for continuous integration: thorough, fail on high.
var CI Option = optFunc(func(c *config) {
	c.concerns = []string{"security", "bugs", "performance", "correctness"}
	c.contextLines = 10
	c.parallel = true
	c.failOn = SeverityHigh
})

// Configuration functions

func WithProvider(p Provider) Option {
	return optFunc(func(c *config) { c.provider = p })
}

func WithModel(model string) Option {
	return optFunc(func(c *config) { c.model = model })
}

func WithConcerns(concerns ...string) Option {
	return optFunc(func(c *config) { c.concerns = concerns })
}

func WithMaxTokens(n int) Option {
	return optFunc(func(c *config) {
		if n > 0 {
			c.maxTokens = n
		}
	})
}

func WithContextLines(n int) Option {
	return optFunc(func(c *config) {
		if n >= 0 {
			c.contextLines = n
		}
	})
}

func WithFailOn(sev Severity) Option {
	return optFunc(func(c *config) { c.failOn = sev })
}

func WithGitContext(enabled bool) Option {
	return optFunc(func(c *config) { c.gitContext = enabled })
}

func WithSymbols(enabled bool) Option {
	return optFunc(func(c *config) { c.symbols = enabled })
}

func WithParallel(enabled bool) Option {
	return optFunc(func(c *config) { c.parallel = enabled })
}

func WithReflection(enabled bool) Option {
	return optFunc(func(c *config) { c.reflection = enabled })
}

// WithPreAnalysis enables or disables static analysis and taint analysis
// as a pre-pass before the LLM review. When enabled, pattern-based static rules
// and data-flow taint analysis are run on the diff, and their findings are
// included in the review results alongside LLM findings.
func WithPreAnalysis(enabled bool) Option {
	return optFunc(func(c *config) { c.preAnalysis = enabled })
}

// WithExclude sets file path patterns to exclude from review.
// Patterns support exact basenames ("go.sum") and glob wildcards ("*.min.js", "*.generated.*").
func WithExclude(patterns ...string) Option {
	return optFunc(func(c *config) { c.exclude = patterns })
}

// WithMinScore sets the minimum reflection score threshold (1-10).
// Findings scoring below this are filtered out during the reflection pass.
func WithMinScore(n int) Option {
	return optFunc(func(c *config) {
		if n >= 1 && n <= 10 {
			c.minScore = n
		}
	})
}

// WithProjectRules injects project-specific rules into the LLM system prompt.
func WithProjectRules(rules string) Option {
	return optFunc(func(c *config) { c.projectRules = rules })
}

// WithFilterMode sets the diff filter mode that controls which findings
// are included as inline comments. See FilterAdded, FilterDiffContext,
// FilterFile, and FilterNone.
func WithFilterMode(mode FilterMode) Option {
	return optFunc(func(c *config) { c.filterMode = mode })
}
