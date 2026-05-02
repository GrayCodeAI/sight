package sight

// Option configures a review operation.
type Option interface {
	apply(*config)
}

type optFunc func(*config)

func (f optFunc) apply(c *config) { f(c) }

type config struct {
	provider    Provider
	model       string
	concerns    []string
	maxTokens   int
	contextLines int
	failOn      Severity
	gitContext  bool
	symbols     bool
	parallel    bool
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
