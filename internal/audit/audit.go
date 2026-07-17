// Package audit provides agent surface security auditing for hawk-eco.
// It scans MCP hooks, permissions, and integration points for security issues.
package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ErrNotImplemented indicates that an audit check has not yet been implemented.
var ErrNotImplemented = errors.New("audit check not implemented")

// AuditTargetType represents a type of audit target.
type AuditTargetType int

const (
	// AuditTargetHooks audits MCP hooks and webhooks.
	AuditTargetHooks AuditTargetType = iota
	// AuditTargetMCP audits MCP server configurations.
	AuditTargetMCP
	// AuditTargetPermissions audits permission configurations.
	AuditTargetPermissions
	// AuditTargetSecrets audits secret storage and access.
	AuditTargetSecrets
	// AuditTargetEndpoints audits external endpoints and APIs.
	AuditTargetEndpoints
)

// AuditTarget represents a target to audit in the codebase.
type AuditTarget struct {
	Type    AuditTargetType
	Path    string
	Recurse bool
	Depth   int
}

// AuditFinding represents a security finding from an audit.
type AuditFinding struct {
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	File           string `json:"file"`
	Line           int    `json:"line"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
	Evidence       string `json:"evidence,omitempty"`
	Source         string `json:"source"`
}

// AuditReport contains the results of an audit.
type AuditReport struct {
	mu       sync.Mutex
	findings []AuditFinding
	stats    AuditStats
}

// AuditStats contains statistics about the audit.
type AuditStats struct {
	TotalTargets       int
	TargetsScanned     int
	FindingsBySeverity map[string]int
	Categories         map[string]int
	DurationMs         int64
}

// AuditScope defines the scope of an audit.
type AuditScope struct {
	Targets     []AuditTarget
	Rules       []string
	Timeout     time.Duration
	MaxDepth    int
	Concurrency int
}

// NewAuditReport creates a new empty audit report.
func NewAuditReport() *AuditReport {
	return &AuditReport{
		findings: make([]AuditFinding, 0),
		stats: AuditStats{
			FindingsBySeverity: make(map[string]int),
			Categories:         make(map[string]int),
		},
	}
}

// AddFinding adds a finding to the report.
func (r *AuditReport) AddFinding(f AuditFinding) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.findings = append(r.findings, f)
	r.stats.TargetsScanned++

	if r.stats.FindingsBySeverity[f.Severity] == 0 {
		r.stats.FindingsBySeverity[f.Severity] = 0
	}
	r.stats.FindingsBySeverity[f.Severity]++

	if r.stats.Categories[f.Category] == 0 {
		r.stats.Categories[f.Category] = 0
	}
	r.stats.Categories[f.Category]++
}

// Findings returns all findings.
func (r *AuditReport) Findings() []AuditFinding {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.findings
}

// Stats returns audit statistics.
func (r *AuditReport) Stats() AuditStats {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.stats
}

// Count returns the total number of findings.
func (r *AuditReport) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.findings)
}

// FilterBySeverity filters findings by severity.
func (r *AuditReport) FilterBySeverity(severity string) []AuditFinding {
	r.mu.Lock()
	defer r.mu.Unlock()

	var result []AuditFinding
	for _, f := range r.findings {
		if f.Severity == severity {
			result = append(result, f)
		}
	}
	return result
}

// FilterByCategory filters findings by category.
func (r *AuditReport) FilterByCategory(category string) []AuditFinding {
	r.mu.Lock()
	defer r.mu.Unlock()

	var result []AuditFinding
	for _, f := range r.findings {
		if f.Category == category {
			result = append(result, f)
		}
	}
	return result
}

// Summary returns a summary of the report.
func (r *AuditReport) Summary() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	count := len(r.findings)
	if count == 0 {
		return "No security findings detected."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Security audit complete: %d findings detected\n", count))
	sb.WriteString(fmt.Sprintf("  - Critical: %d\n", r.stats.FindingsBySeverity["critical"]))
	sb.WriteString(fmt.Sprintf("  - High: %d\n", r.stats.FindingsBySeverity["high"]))
	sb.WriteString(fmt.Sprintf("  - Medium: %d\n", r.stats.FindingsBySeverity["medium"]))
	sb.WriteString(fmt.Sprintf("  - Low: %d\n", r.stats.FindingsBySeverity["low"]))
	sb.WriteString("\nCategories:\n")
	for cat, cnt := range r.stats.Categories {
		sb.WriteString(fmt.Sprintf("  - %s: %d\n", cat, cnt))
	}

	return sb.String()
}

// Audit performs a security audit on the given targets.
// It returns a report with all findings.
func Audit(ctx context.Context, scope *AuditScope) (*AuditReport, error) {
	if scope == nil {
		return nil, fmt.Errorf("scope cannot be nil")
	}

	report := NewAuditReport()
	report.stats.TotalTargets = len(scope.Targets)

	// Apply default rules if none specified
	if len(scope.Rules) == 0 {
		scope.Rules = DefaultRules()
	}

	// Run concurrent audits
	var wg sync.WaitGroup
	sem := make(chan struct{}, scope.Concurrency)

	for _, target := range scope.Targets {
		wg.Add(1)
		go func(t AuditTarget) {
			defer wg.Done()

			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			if err := auditTarget(ctx, t, scope, report); err != nil {
				report.AddFinding(AuditFinding{
					Severity:    "medium",
					Category:    "audit_error",
					File:        t.Path,
					Description: fmt.Sprintf("Audit failed: %v", err),
					Source:      "audit",
				})
			}
		}(target)

		// Respect timeout
		select {
		case <-ctx.Done():
			report.AddFinding(AuditFinding{
				Severity:    "medium",
				Category:    "timeout",
				Description: "Audit timed out",
				Source:      "audit",
			})
			return report, ctx.Err()
		default:
		}
	}

	wg.Wait()
	return report, nil
}

// auditTarget performs audit on a single target.
func auditTarget(ctx context.Context, target AuditTarget, scope *AuditScope, report *AuditReport) error {
	switch target.Type {
	case AuditTargetHooks:
		return auditHooks(ctx, target, scope, report)
	case AuditTargetMCP:
		return auditMCPServer(ctx, target, scope, report)
	case AuditTargetPermissions:
		return auditPermissions(ctx, target, scope, report)
	case AuditTargetSecrets:
		return auditSecrets(ctx, target, scope, report)
	case AuditTargetEndpoints:
		return auditEndpoints(ctx, target, scope, report)
	default:
		return fmt.Errorf("unknown audit target type: %d", target.Type)
	}
}

// DefaultRules returns the default security audit rules.
func DefaultRules() []string {
	return []string{
		"detect_unauthenticated_endpoints",
		"detect_hardcoded_secrets",
		"detect_missing_input_validation",
		"detect_excessive_permissions",
		"detect_insecure_mcp_config",
		"detect_webhook_validation",
	}
}

// auditHooks performs audit on MCP hooks.
func auditHooks(ctx context.Context, target AuditTarget, scope *AuditScope, report *AuditReport) error {
	// Placeholder: implement hook auditing
	return ErrNotImplemented
}

// auditMCPServer performs audit on MCP server configurations.
func auditMCPServer(ctx context.Context, target AuditTarget, scope *AuditScope, report *AuditReport) error {
	// Placeholder: implement MCP config auditing
	return ErrNotImplemented
}

// auditPermissions performs audit on permission configurations.
func auditPermissions(ctx context.Context, target AuditTarget, scope *AuditScope, report *AuditReport) error {
	// Placeholder: implement permission auditing
	return ErrNotImplemented
}

// auditSecrets performs audit on secret storage and access.
func auditSecrets(ctx context.Context, target AuditTarget, scope *AuditScope, report *AuditReport) error {
	// Placeholder: implement secret auditing
	return ErrNotImplemented
}

// auditEndpoints performs audit on external endpoints and APIs.
func auditEndpoints(ctx context.Context, target AuditTarget, scope *AuditScope, report *AuditReport) error {
	// Placeholder: implement endpoint auditing
	return ErrNotImplemented
}

// ValidateRule checks if a rule is valid.
func ValidateRule(rule string) bool {
	validRules := map[string]bool{
		"detect_unauthenticated_endpoints": true,
		"detect_hardcoded_secrets":         true,
		"detect_missing_input_validation":  true,
		"detect_excessive_permissions":     true,
		"detect_insecure_mcp_config":       true,
		"detect_webhook_validation":        true,
	}
	return validRules[rule]
}

// Category represents common vulnerability categories.
type Category struct {
	Name        string
	Description string
	Severity    string
}

// Common categories
var (
	CriticalCategories = []Category{
		{Name: "RCE", Description: "Remote Code Execution", Severity: "critical"},
		{Name: "SQL Injection", Description: "SQL Injection vulnerability", Severity: "critical"},
		{Name: "Auth Bypass", Description: "Authentication bypass", Severity: "critical"},
	}

	HighCategories = []Category{
		{Name: "SSRF", Description: "Server-Side Request Forgery", Severity: "high"},
		{Name: "Path Traversal", Description: "Path traversal vulnerability", Severity: "high"},
		{Name: "Command Injection", Description: "OS command injection", Severity: "high"},
	}

	MediumCategories = []Category{
		{Name: "XSS", Description: "Cross-Site Scripting", Severity: "medium"},
		{Name: "IDOR", Description: "Insecure Direct Object Reference", Severity: "medium"},
		{Name: "Missing Encryption", Description: "Missing TLS/encryption", Severity: "medium"},
	}

	LowCategories = []Category{
		{Name: "Info Exposure", Description: "Information exposure", Severity: "low"},
		{Name: "Missing Headers", Description: "Missing security headers", Severity: "low"},
		{Name: "Verbose Errors", Description: "Verbose error messages", Severity: "low"},
	}
)

// Common patterns for security detection
var (
	SecretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}`),
		regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*["'][^"']{16,}`),
		regexp.MustCompile(`(?i)secret[_-]?key\s*[:=]\s*["'][^"']{16,}`),
		regexp.MustCompile(`(?i)token\s*[:=]\s*["'][^"']{20,}`),
		regexp.MustCompile(`(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["'][A-Z0-9]{16}`),
		regexp.MustCompile(`(?i)hardcoded.*secret`),
		regexp.MustCompile(`(?i)(sk|pk)_[a-zA-Z0-9]{20,}`),
	}

	AuthBypassPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(bypass|disable|skip|ignore|no.*auth|without.*auth)`),
		regexp.MustCompile(`(?i)(admin.*true|superuser|root.*access)`),
	}
)

// HTTPClient provides HTTP access for auditing endpoints.
type HTTPClient struct {
	client *http.Client
}

// NewHTTPClient creates a new HTTP client.
func NewHTTPClient(timeout time.Duration) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Get performs a GET request to an endpoint.
func (h *HTTPClient) Get(ctx context.Context, url string) (*HTTPResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	return &HTTPResponse{StatusCode: resp.StatusCode, Body: bodyBytes}, nil
}

// HTTPResponse represents an HTTP response.
type HTTPResponse struct {
	StatusCode int
	Body       []byte
}
