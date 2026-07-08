// Package tool provides browser automation capabilities via HTTP.
package tool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// BrowserOptions configures browser behavior.
type BrowserOptions struct {
	Timeout      time.Duration
	Follow       bool
	MaxRedirects int
	Headers      map[string]string
}

// DefaultBrowserOptions returns default browser options.
func DefaultBrowserOptions() BrowserOptions {
	return BrowserOptions{
		Timeout:      30 * time.Second,
		Follow:       true,
		MaxRedirects: 10,
		Headers:      make(map[string]string),
	}
}

// BrowserTool provides browser automation capabilities via HTTP.
type BrowserTool struct {
	mu      sync.Mutex
	client  *http.Client
	opts    BrowserOptions
	visited map[string]bool
}

// NewBrowserTool creates a new browser tool.
func NewBrowserTool(opts ...func(*BrowserOptions)) *BrowserTool {
	options := DefaultBrowserOptions()
	for _, opt := range opts {
		opt(&options)
	}

	client := &http.Client{
		Timeout: options.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= options.MaxRedirects {
				return fmt.Errorf("max redirects reached")
			}
			if !options.Follow {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &BrowserTool{
		client:  client,
		opts:    options,
		visited: make(map[string]bool),
	}
}

// Do performs an HTTP request.
func (b *BrowserTool) Do(ctx context.Context, method, urlStr string, body io.Reader) (*Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}

	for key, value := range b.opts.Headers {
		req.Header.Set(key, value)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	b.visited[urlStr] = true

	return &Response{
		StatusCode:    resp.StatusCode,
		Headers:       resp.Header,
		Body:          bodyBytes,
		URL:           resp.Request.URL.String(),
		RequestMethod: method,
	}, nil
}

// Get performs a GET request.
func (b *BrowserTool) Get(ctx context.Context, urlStr string) (*Response, error) {
	return b.Do(ctx, "GET", urlStr, nil)
}

// Post performs a POST request.
func (b *BrowserTool) Post(ctx context.Context, urlStr string, body io.Reader) (*Response, error) {
	return b.Do(ctx, "POST", urlStr, body)
}

// SetHeader sets a default header.
func (b *BrowserTool) SetHeader(key, value string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.opts.Headers[key] = value
}

// Response represents an HTTP response.
type Response struct {
	StatusCode    int
	Headers       http.Header
	Body          []byte
	URL           string
	RequestMethod string
}

// Text returns the response body as text.
func (r *Response) Text() string {
	return string(r.Body)
}

// JSON attempts to parse the response body as JSON.
func (r *Response) JSON() (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := json.Unmarshal(r.Body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// IsSuccess returns true if status code is 2xx.
func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// Formatter provides formatted output for browser tool results.
type Formatter struct {
	indent int
}

// NewFormatter creates a new formatter.
func NewFormatter(indent int) *Formatter {
	return &Formatter{indent: indent}
}

// FormatResponse formats a response.
func (f *Formatter) FormatResponse(resp *Response) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP %s %d\n", resp.RequestMethod, resp.StatusCode))
	sb.WriteString(fmt.Sprintf("URL: %s\n", resp.URL))

	sb.WriteString("Headers:\n")
	for key, values := range resp.Headers {
		for _, v := range values {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", key, v))
		}
	}

	sb.WriteString(fmt.Sprintf("\nBody (%d bytes):\n", len(resp.Body)))
	body := string(resp.Body)
	if len(body) > 1000 {
		sb.WriteString(body[:1000])
		sb.WriteString("\n... (truncated)\n")
	} else {
		sb.WriteString(body)
	}

	return sb.String()
}

// ValidateURL validates a URL.
func ValidateURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsed.Scheme == "" {
		return nil, fmt.Errorf("URL missing scheme")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("URL missing host")
	}

	return parsed, nil
}

// WebhookTester tests webhooks by sending test requests.
type WebhookTester struct {
	browser *BrowserTool
}

// NewWebhookTester creates a new webhook tester.
func NewWebhookTester(opts ...func(*BrowserOptions)) *WebhookTester {
	return &WebhookTester{
		browser: NewBrowserTool(opts...),
	}
}

// SendTestRequest sends a test request to a webhook URL.
func (w *WebhookTester) SendTestRequest(ctx context.Context, webhookURL string, payload interface{}) (*Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return w.browser.Post(ctx, webhookURL, bytes.NewReader(body))
}

// ValidateWebhook validates a webhook endpoint.
func (w *WebhookTester) ValidateWebhook(ctx context.Context, webhookURL string, expectedStatus int) error {
	resp, err := w.browser.Get(ctx, webhookURL)
	if err != nil {
		return err
	}

	if resp.StatusCode != expectedStatus {
		return fmt.Errorf("expected status %d, got %d", expectedStatus, resp.StatusCode)
	}

	return nil
}
