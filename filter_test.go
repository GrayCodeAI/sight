package sight_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrayCodeAI/sight"
)

// filterProvider is a mock provider specifically for FilterFindings tests.
type filterProvider struct {
	response string
	err      error
	mu       sync.Mutex
	calls    int
	delay    time.Duration
}

func (p *filterProvider) Chat(ctx context.Context, messages []sight.Message, opts sight.ChatOpts) (*sight.Response, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()

	if p.delay > 0 {
		select {
		case <-time.After(p.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if p.err != nil {
		return nil, p.err
	}
	return &sight.Response{
		Content:    p.response,
		TokensUsed: 100,
	}, nil
}

func (p *filterProvider) getCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func TestFilterFindings_ValidProvider(t *testing.T) {
	provider := &filterProvider{
		response: "CONFIRMED: yes\nCONFIDENCE: 0.9\nREASONING: real issue",
	}

	findings := []sight.Finding{
		{
			Concern:  "security",
			Severity: sight.SeverityHigh,
			File:     "handler.go",
			Line:     10,
			Message:  "SQL injection vulnerability",
			Fix:      "Use parameterized queries",
		},
		{
			Concern:  "style",
			Severity: sight.SeverityLow,
			File:     "handler.go",
			Line:     20,
			Message:  "Line too long",
		},
	}

	fileContents := map[string]string{
		"handler.go": "package main\n\nimport \"database/sql\"\n\nfunc main() {\n\t// code\n}\n",
	}

	config := sight.DefaultFilterConfig()

	confirmed, results, err := sight.FilterFindings(
		context.Background(), provider, findings, fileContents, config,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Low severity finding (SeverityLow < SeverityMedium) should pass through without filtering
	// High severity finding should go through validation and be confirmed
	if len(results) != 1 {
		t.Fatalf("expected 1 filter result (only high severity), got %d", len(results))
	}

	if !results[0].Confirmed {
		t.Error("expected finding to be confirmed")
	}

	// Both the pass-through low finding and the confirmed high finding should be present
	if len(confirmed) != 2 {
		t.Errorf("expected 2 confirmed findings, got %d", len(confirmed))
	}

	if provider.getCalls() != 1 {
		t.Errorf("expected 1 provider call, got %d", provider.getCalls())
	}
}

func TestFilterFindings_NilProvider(t *testing.T) {
	findings := []sight.Finding{
		{Severity: sight.SeverityHigh, Message: "test"},
	}

	_, _, err := sight.FilterFindings(
		context.Background(), nil, findings, nil, sight.DefaultFilterConfig(),
	)
	if err != sight.ErrNoProvider {
		t.Errorf("expected ErrNoProvider, got %v", err)
	}
}

func TestFilterFindings_InvalidJSON(t *testing.T) {
	// Provider returns non-JSON response; parseFilterResponse should handle gracefully
	provider := &filterProvider{
		response: "this is not valid structured output",
	}

	findings := []sight.Finding{
		{
			Severity: sight.SeverityHigh,
			File:     "test.go",
			Line:     5,
			Message:  "test finding",
		},
	}

	config := sight.DefaultFilterConfig()

	confirmed, results, err := sight.FilterFindings(
		context.Background(), provider, findings, nil, config,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// With no "confirmed: no" or "false positive" in response, default is confirmed=true
	if !results[0].Confirmed {
		t.Error("expected finding to be confirmed when response lacks explicit rejection")
	}

	// Default confidence should be 0.7 when parsing fails
	if results[0].Confidence != 0.7 {
		t.Errorf("expected default confidence 0.7, got %f", results[0].Confidence)
	}

	// The confirmed finding should be present
	if len(confirmed) < 1 {
		t.Error("expected at least 1 confirmed finding")
	}
}

func TestFilterFindings_ContextCancellation(t *testing.T) {
	provider := &filterProvider{
		response: "CONFIRMED: yes\nCONFIDENCE: 0.9",
		delay:    5 * time.Second,
	}

	findings := []sight.Finding{
		{Severity: sight.SeverityHigh, File: "test.go", Line: 1, Message: "finding 1"},
		{Severity: sight.SeverityHigh, File: "test.go", Line: 2, Message: "finding 2"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	config := sight.DefaultFilterConfig()

	_, _, err := sight.FilterFindings(ctx, provider, findings, nil, config)
	if err != sight.ErrContextCancelled {
		t.Errorf("expected ErrContextCancelled, got %v", err)
	}
}

func TestFilterFindings_ConcurrentExecution(t *testing.T) {
	var maxConcurrent int32
	var currentConcurrent int32

	provider := &filterProvider{
		response: "CONFIRMED: yes\nCONFIDENCE: 0.8\nREASONING: valid",
	}

	// Override delay to track concurrency
	origDelay := provider.delay

	findings := make([]sight.Finding, 20)
	for i := range findings {
		findings[i] = sight.Finding{
			Severity: sight.SeverityHigh,
			File:     "test.go",
			Line:     i + 1,
			Message:  fmt.Sprintf("finding %d", i),
		}
	}

	config := sight.FilterConfig{
		MinSeverity:         sight.SeverityMedium,
		ConfidenceThreshold: 0.5,
		MaxParallel:         5,
		BatchSize:           10,
	}

	// Create a concurrency-tracking provider
	concProvider := &concurrencyTracker{
		response:        "CONFIRMED: yes\nCONFIDENCE: 0.8",
		maxConcurrent:   &maxConcurrent,
		curConcurrent:   &currentConcurrent,
		simulatedDelay:  10 * time.Millisecond,
	}

	_, results, err := sight.FilterFindings(
		context.Background(), concProvider, findings, nil, config,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 20 {
		t.Errorf("expected 20 results, got %d", len(results))
	}

	observedMax := atomic.LoadInt32(&maxConcurrent)
	if observedMax > 5 {
		t.Errorf("max concurrency %d exceeded limit of 5", observedMax)
	}
	if observedMax < 2 {
		t.Errorf("expected concurrent execution, but max concurrency was %d", observedMax)
	}

	_ = origDelay // suppress unused warning
}

type concurrencyTracker struct {
	response        string
	maxConcurrent   *int32
	curConcurrent   *int32
	simulatedDelay  time.Duration
	mu              sync.Mutex
}

func (c *concurrencyTracker) Chat(ctx context.Context, messages []sight.Message, opts sight.ChatOpts) (*sight.Response, error) {
	cur := atomic.AddInt32(c.curConcurrent, 1)
	// Atomically update max
	for {
		old := atomic.LoadInt32(c.maxConcurrent)
		if cur <= old || atomic.CompareAndSwapInt32(c.maxConcurrent, old, cur) {
			break
		}
	}

	time.Sleep(c.simulatedDelay)
	atomic.AddInt32(c.curConcurrent, -1)

	return &sight.Response{
		Content:    c.response,
		TokensUsed: 50,
	}, nil
}

func TestFilterFindings_EmptyFindings(t *testing.T) {
	provider := &filterProvider{
		response: "CONFIRMED: yes",
	}

	config := sight.DefaultFilterConfig()

	confirmed, results, err := sight.FilterFindings(
		context.Background(), provider, nil, nil, config,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(confirmed) != 0 {
		t.Errorf("expected 0 confirmed findings, got %d", len(confirmed))
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
	if provider.getCalls() != 0 {
		t.Errorf("expected 0 provider calls, got %d", provider.getCalls())
	}
}

func TestFilterFindings_AllBelowMinSeverity(t *testing.T) {
	provider := &filterProvider{
		response: "CONFIRMED: yes",
	}

	findings := []sight.Finding{
		{Severity: sight.SeverityLow, Message: "low finding"},
		{Severity: sight.SeverityInfo, Message: "info finding"},
	}

	config := sight.DefaultFilterConfig()

	confirmed, results, err := sight.FilterFindings(
		context.Background(), provider, findings, nil, config,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All findings are below min severity, so they pass through without filtering
	if len(confirmed) != 2 {
		t.Errorf("expected 2 pass-through findings, got %d", len(confirmed))
	}
	if len(results) != 0 {
		t.Errorf("expected 0 filter results, got %d", len(results))
	}
	if provider.getCalls() != 0 {
		t.Errorf("expected 0 provider calls, got %d", provider.getCalls())
	}
}

func TestFilterFindings_FilteredByConfidence(t *testing.T) {
	provider := &filterProvider{
		response: "CONFIRMED: yes\nCONFIDENCE: 0.3\nREASONING: uncertain",
	}

	findings := []sight.Finding{
		{Severity: sight.SeverityHigh, File: "test.go", Line: 1, Message: "low confidence finding"},
	}

	config := sight.FilterConfig{
		MinSeverity:         sight.SeverityMedium,
		ConfidenceThreshold: 0.6,
		MaxParallel:         5,
		BatchSize:           10,
	}

	confirmed, results, err := sight.FilterFindings(
		context.Background(), provider, findings, nil, config,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// Finding is confirmed but below confidence threshold, so it should be filtered out
	if results[0].Confidence != 0.3 {
		t.Errorf("expected confidence 0.3, got %f", results[0].Confidence)
	}

	if len(confirmed) != 0 {
		t.Errorf("expected 0 confirmed findings (below threshold), got %d", len(confirmed))
	}
}

func TestFilterFindings_RejectedByProvider(t *testing.T) {
	provider := &filterProvider{
		response: "CONFIRMED: no\nCONFIDENCE: 0.95\nREASONING: false positive",
	}

	findings := []sight.Finding{
		{Severity: sight.SeverityHigh, File: "test.go", Line: 1, Message: "false positive"},
	}

	config := sight.DefaultFilterConfig()

	confirmed, results, err := sight.FilterFindings(
		context.Background(), provider, findings, nil, config,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Confirmed {
		t.Error("expected finding to be rejected")
	}

	if len(confirmed) != 0 {
		t.Errorf("expected 0 confirmed findings, got %d", len(confirmed))
	}
}

func TestFilterFindings_ProviderError(t *testing.T) {
	provider := &filterProvider{
		err: fmt.Errorf("rate limited"),
	}

	findings := []sight.Finding{
		{Severity: sight.SeverityHigh, File: "test.go", Line: 1, Message: "test"},
	}

	config := sight.DefaultFilterConfig()

	confirmed, results, err := sight.FilterFindings(
		context.Background(), provider, findings, nil, config,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// On provider error, finding defaults to confirmed with 0.5 confidence
	if !results[0].Confirmed {
		t.Error("expected finding to be confirmed on provider error (conservative default)")
	}
	if results[0].Confidence != 0.5 {
		t.Errorf("expected confidence 0.5 on error, got %f", results[0].Confidence)
	}

	// 0.5 < 0.6 threshold, so it should be filtered out
	if len(confirmed) != 0 {
		t.Errorf("expected 0 confirmed findings (below threshold on error), got %d", len(confirmed))
	}
}

func TestFilterFindings_CodeContext(t *testing.T) {
	// Test that file content is properly extracted for the provider
	var capturedMessages []sight.Message
	provider := &captureProvider{
		response: "CONFIRMED: yes\nCONFIDENCE: 0.9",
		messages: &capturedMessages,
	}

	fileContents := map[string]string{
		"test.go": "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n",
	}

	findings := []sight.Finding{
		{Severity: sight.SeverityHigh, File: "test.go", Line: 5, Message: "test finding"},
	}

	config := sight.DefaultFilterConfig()

	_, _, err := sight.FilterFindings(
		context.Background(), provider, findings, fileContents, config,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(capturedMessages) == 0 {
		t.Fatal("expected provider to receive messages")
	}

	content := capturedMessages[0].Content
	if !strings.Contains(content, "test.go") {
		t.Error("expected prompt to contain file name")
	}
	if !strings.Contains(content, "test finding") {
		t.Error("expected prompt to contain finding message")
	}
}

type captureProvider struct {
	response string
	messages *[]sight.Message
	mu       sync.Mutex
}

func (p *captureProvider) Chat(ctx context.Context, messages []sight.Message, opts sight.ChatOpts) (*sight.Response, error) {
	p.mu.Lock()
	*p.messages = append(*p.messages, messages...)
	p.mu.Unlock()
	return &sight.Response{
		Content:    p.response,
		TokensUsed: 100,
	}, nil
}
