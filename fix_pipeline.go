package sight

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// String returns a human-readable summary of the fix suggestion.
func (f FixSuggestion) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s\n", f.Category, f.Title)
	fmt.Fprintf(&b, "  Finding:   %s\n", f.FindingID)
	fmt.Fprintf(&b, "  Severity:  %s\n", f.Severity)
	fmt.Fprintf(&b, "  Effort:    %s\n", f.EstimatedEffort)
	fmt.Fprintf(&b, "  Priority:  %d\n", f.Priority)
	fmt.Fprintf(&b, "  Confidence: %.0f%%\n", f.Confidence*100)
	fmt.Fprintf(&b, "  Description: %s\n", f.Description)
	if f.FixCode != "" {
		fmt.Fprintf(&b, "  Suggested Fix:\n%s", indentBlock(f.FixCode, "    "))
	}
	return b.String()
}

// indentBlock prefixes every line of s with the given indent string.
func indentBlock(s, indent string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = indent + line
	}
	return strings.Join(lines, "\n")
}

// FixRule is a pattern-matching rule that, when a Finding matches, produces a
// FixSuggestion. Rules are evaluated in the order they are registered.
type FixRule struct {
	// MatchFn returns true when this rule applies to the given Finding.
	MatchFn func(Finding) bool
	// Generator produces a FixSuggestion for a matched Finding.
	Generator func(Finding) FixSuggestion
}

// FixPipeline evaluates a set of FixRules against findings and returns
// deduplicated, sorted fix suggestions.
type FixPipeline struct {
	mu    sync.RWMutex
	rules []FixRule
}

// NewFixPipeline returns a pipeline pre-loaded with the built-in remediation
// rules. Additional rules can be registered with AddRule.
func NewFixPipeline() *FixPipeline {
	p := &FixPipeline{}
	p.registerBuiltinRules()
	return p
}

// AddRule appends a custom fix rule to the pipeline. It is safe for
// concurrent use.
func (p *FixPipeline) AddRule(rule FixRule) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = append(p.rules, rule)
}

// GenerateFixes evaluates all registered rules against the supplied findings,
// deduplicates per finding (keeping the highest-confidence suggestion), and
// returns results sorted by Priority (ascending) then Confidence (descending).
func (p *FixPipeline) GenerateFixes(findings []Finding) []FixSuggestion {
	p.mu.RLock()
	rules := make([]FixRule, len(p.rules))
	copy(rules, p.rules)
	p.mu.RUnlock()

	// best tracks the highest-confidence suggestion per finding ID.
	type candidate struct {
		fix  FixSuggestion
		rank int // tie-breaker: lower index = registered earlier
	}
	best := make(map[string]candidate)

	for i, f := range findings {
		fid := findingID(f, i)
		for ri, rule := range rules {
			if !rule.MatchFn(f) {
				continue
			}
			suggestion := rule.Generator(f)
			suggestion.FindingID = fid

			prev, exists := best[fid]
			if !exists || suggestion.Confidence > prev.fix.Confidence ||
				(suggestion.Confidence == prev.fix.Confidence && ri < prev.rank) {
				best[fid] = candidate{fix: suggestion, rank: ri}
			}
		}
	}

	// Collect and sort.
	out := make([]FixSuggestion, 0, len(best))
	for _, c := range best {
		out = append(out, c.fix)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].Confidence > out[j].Confidence
	})
	return out
}

// findingID builds a deterministic identifier from the Finding's key fields.
// The Finding struct has no dedicated ID field, so we compose one.
func findingID(f Finding, index int) string {
	return fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.Concern)
}

// ---------------------------------------------------------------------------
// Built-in rules
// ---------------------------------------------------------------------------

// registerBuiltinRules adds the default set of pattern-matching fix rules.
func (p *FixPipeline) registerBuiltinRules() {
	p.rules = []FixRule{
		sqlInjectionRule(),
		xssRule(),
		hardcodedSecretRule(),
		inputValidationRule(),
		weakCryptoRule(),
		pathTraversalRule(),
		ssrfRule(),
	}
}

// sqlInjectionRule detects SQL injection concerns and suggests parameterized queries.
func sqlInjectionRule() FixRule {
	return FixRule{
		MatchFn: func(f Finding) bool {
			lower := strings.ToLower(f.Concern + " " + f.Message + " " + f.CWE)
			return strings.Contains(lower, "sql injection") ||
				strings.Contains(lower, "sqli") ||
				f.CWE == "CWE-89"
		},
		Generator: func(f Finding) FixSuggestion {
			return FixSuggestion{
				Title:       "Use parameterized queries to prevent SQL injection",
				Description: fmt.Sprintf("The code in %s:%d uses string concatenation or formatting to build SQL queries, which enables SQL injection. Replace with parameterized queries (placeholders) so user input is never interpolated into the SQL string.", f.File, f.Line),
				FixCode:     `// Before (vulnerable):\n//   query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userInput)\n//\n// After (safe):\n//   query := "SELECT * FROM users WHERE id = $1"\n//   rows, err := db.Query(query, userInput)`,
				Confidence:      0.85,
				Category:        "injection",
				Severity:        f.Severity.String(),
				EstimatedEffort: "easy",
				Priority:        1,
			}
		},
	}
}

// xssRule detects cross-site scripting concerns and suggests HTML escaping.
func xssRule() FixRule {
	return FixRule{
		MatchFn: func(f Finding) bool {
			lower := strings.ToLower(f.Concern + " " + f.Message + " " + f.CWE)
			return strings.Contains(lower, "xss") ||
				strings.Contains(lower, "cross-site scripting") ||
				f.CWE == "CWE-79"
		},
		Generator: func(f Finding) FixSuggestion {
			return FixSuggestion{
				Title:       "Escape or sanitize user input before rendering in HTML",
				Description: fmt.Sprintf("The code in %s:%d renders user-controlled data into HTML without proper escaping, enabling cross-site scripting. Use html.EscapeString or a template engine with auto-escaping enabled (e.g. html/template).", f.File, f.Line),
				FixCode:     `// Option 1 — manual escaping:\n//   import "html"\n//   safe := html.EscapeString(userInput)\n//\n// Option 2 — use html/template (auto-escapes by default):\n//   tmpl := template.Must(template.New("page").Parse(tmplStr))\n//   tmpl.Execute(w, data)`,
				Confidence:      0.85,
				Category:        "xss",
				Severity:        f.Severity.String(),
				EstimatedEffort: "easy",
				Priority:        1,
			}
		},
	}
}

// hardcodedSecretRule detects hardcoded credentials, tokens, or API keys.
func hardcodedSecretRule() FixRule {
	return FixRule{
		MatchFn: func(f Finding) bool {
			lower := strings.ToLower(f.Concern + " " + f.Message + " " + f.CWE)
			return strings.Contains(lower, "hardcoded") ||
				strings.Contains(lower, "hard-coded") ||
				strings.Contains(lower, "secret") ||
				strings.Contains(lower, "credential") ||
				strings.Contains(lower, "api key") ||
				strings.Contains(lower, "password") ||
				f.CWE == "CWE-798"
		},
		Generator: func(f Finding) FixSuggestion {
			return FixSuggestion{
				Title:       "Move secrets to environment variables or a secret manager",
				Description: fmt.Sprintf("The code in %s:%d contains a hardcoded secret, credential, or API key. Hardcoded secrets are easily leaked through source control. Load secrets from environment variables or a dedicated secret manager (e.g. AWS Secrets Manager, HashiCorp Vault).", f.File, f.Line),
				FixCode:     `// Before (vulnerable):\n//   const apiKey = "sk-abc123..."\n//\n// After (safe):\n//   import "os"\n//   apiKey := os.Getenv("API_KEY")\n//   if apiKey == "" {\n//       log.Fatal("API_KEY not set")\n//   }`,
				Confidence:      0.90,
				Category:        "auth",
				Severity:        f.Severity.String(),
				EstimatedEffort: "trivial",
				Priority:        2,
			}
		},
	}
}

// inputValidationRule detects missing or insufficient input validation.
func inputValidationRule() FixRule {
	return FixRule{
		MatchFn: func(f Finding) bool {
			lower := strings.ToLower(f.Concern + " " + f.Message + " " + f.CWE)
			return strings.Contains(lower, "input validation") ||
				strings.Contains(lower, "missing validation") ||
				strings.Contains(lower, "unsanitized") ||
				f.CWE == "CWE-20"
		},
		Generator: func(f Finding) FixSuggestion {
			return FixSuggestion{
				Title:       "Add input validation middleware or handler-level checks",
				Description: fmt.Sprintf("The code in %s:%d processes user input without adequate validation. Add validation at the handler or middleware layer to reject malformed input early. Use a validation library (e.g. go-playground/validator) or enforce constraints explicitly.", f.File, f.Line),
				FixCode:     `// Example with go-playground/validator:\n//   import "github.com/go-playground/validator/v10"\n//   var validate = validator.New()\n//   if err := validate.Struct(input); err != nil {\n//       http.Error(w, "invalid input", http.StatusBadRequest)\n//       return\n//   }`,
				Confidence:      0.80,
				Category:        "input-validation",
				Severity:        f.Severity.String(),
				EstimatedEffort: "moderate",
				Priority:        3,
			}
		},
	}
}

// weakCryptoRule detects usage of weak or deprecated cryptographic algorithms.
func weakCryptoRule() FixRule {
	return FixRule{
		MatchFn: func(f Finding) bool {
			lower := strings.ToLower(f.Concern + " " + f.Message + " " + f.CWE)
			return strings.Contains(lower, "weak crypto") ||
				strings.Contains(lower, "weak hash") ||
				strings.Contains(lower, "md5") ||
				strings.Contains(lower, "sha1") ||
				strings.Contains(lower, "des ") ||
				strings.Contains(lower, "rc4") ||
				f.CWE == "CWE-327" ||
				f.CWE == "CWE-328"
		},
		Generator: func(f Finding) FixSuggestion {
			return FixSuggestion{
				Title:       "Replace weak cryptographic algorithm with a modern alternative",
				Description: fmt.Sprintf("The code in %s:%d uses a weak or deprecated cryptographic algorithm. Replace MD5/SHA-1 with SHA-256 or SHA-3 for hashing, and use AES-GCM or ChaCha20-Poly1305 for symmetric encryption.", f.File, f.Line),
				FixCode:     `// Hashing — replace MD5/SHA-1:\n//   import "crypto/sha256"\n//   hash := sha256.Sum256(data)\n//\n// Encryption — use AES-GCM:\n//   import "crypto/aes" + "crypto/cipher"\n//   block, _ := aes.NewCipher(key)\n//   gcm, _ := cipher.NewGCM(block)`,
				Confidence:      0.90,
				Category:        "crypto",
				Severity:        f.Severity.String(),
				EstimatedEffort: "moderate",
				Priority:        2,
			}
		},
	}
}

// pathTraversalRule detects path traversal vulnerabilities.
func pathTraversalRule() FixRule {
	return FixRule{
		MatchFn: func(f Finding) bool {
			lower := strings.ToLower(f.Concern + " " + f.Message + " " + f.CWE)
			return strings.Contains(lower, "path traversal") ||
				strings.Contains(lower, "directory traversal") ||
				strings.Contains(lower, "path injection") ||
				f.CWE == "CWE-22"
		},
		Generator: func(f Finding) FixSuggestion {
			return FixSuggestion{
				Title:       "Sanitize file paths with filepath.Clean and base-path check",
				Description: fmt.Sprintf("The code in %s:%d constructs a file path from user input without proper sanitization, enabling path traversal attacks. Use filepath.Clean to normalize the path and verify it stays within the intended base directory.", f.File, f.Line),
				FixCode:     `// import "path/filepath"\n//\n// base := "/var/data/uploads"\n// cleaned := filepath.Clean(filepath.Join(base, userInput))\n// if !strings.HasPrefix(cleaned, base) {\n//     http.Error(w, "invalid path", http.StatusBadRequest)\n//     return\n// }`,
				Confidence:      0.85,
				Category:        "input-validation",
				Severity:        f.Severity.String(),
				EstimatedEffort: "easy",
				Priority:        2,
			}
		},
	}
}

// ssrfRule detects server-side request forgery vulnerabilities.
func ssrfRule() FixRule {
	return FixRule{
		MatchFn: func(f Finding) bool {
			lower := strings.ToLower(f.Concern + " " + f.Message + " " + f.CWE)
			return strings.Contains(lower, "ssrf") ||
				strings.Contains(lower, "server-side request forgery") ||
				strings.Contains(lower, "request forgery") ||
				f.CWE == "CWE-918"
		},
		Generator: func(f Finding) FixSuggestion {
			return FixSuggestion{
				Title:       "Validate outbound URLs against an allowlist",
				Description: fmt.Sprintf("The code in %s:%d makes an HTTP request to a user-supplied URL, enabling server-side request forgery. Validate the URL against an allowlist of permitted hosts and schemes before issuing the request. Reject private IP ranges and localhost.", f.File, f.Line),
				FixCode:     `// import "net/url"\n//\n// allowedHosts := map[string]bool{"api.example.com": true}\n// parsed, err := url.Parse(userURL)\n// if err != nil || !allowedHosts[parsed.Hostname()] {\n//     return fmt.Errorf("URL not allowed: %s", userURL)\n// }`,
				Confidence:      0.80,
				Category:        "ssrf",
				Severity:        f.Severity.String(),
				EstimatedEffort: "moderate",
				Priority:        2,
			}
		},
	}
}
