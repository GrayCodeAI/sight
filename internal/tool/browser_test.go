package tool

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultBrowserOptions(t *testing.T) {
	opts := DefaultBrowserOptions()

	if opts.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", opts.Timeout)
	}
	if !opts.Follow {
		t.Error("expected Follow=true")
	}
	if opts.MaxRedirects != 10 {
		t.Errorf("expected max redirects 10, got %d", opts.MaxRedirects)
	}
	if opts.Headers == nil {
		t.Error("expected non-nil headers map")
	}
}

func TestNewBrowserTool(t *testing.T) {
	browser := NewBrowserTool()

	if browser == nil {
		t.Fatal("expected non-nil browser")
	}
	if browser.client == nil {
		t.Error("expected non-nil HTTP client")
	}
	if browser.opts.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", browser.opts.Timeout)
	}
}

func TestSetHeader(t *testing.T) {
	browser := NewBrowserTool()

	browser.SetHeader("Authorization", "Bearer token123")
	browser.SetHeader("Content-Type", "application/json")

	if browser.opts.Headers["Authorization"] != "Bearer token123" {
		t.Errorf("expected Authorization header, got %s", browser.opts.Headers["Authorization"])
	}
	if browser.opts.Headers["Content-Type"] != "application/json" {
		t.Errorf("expected Content-Type header, got %s", browser.opts.Headers["Content-Type"])
	}
}

func TestBrowserDo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	browser := NewBrowserTool()
	ctx := context.Background()
	resp, err := browser.Do(ctx, "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if resp.Text() != "OK" {
		t.Errorf("expected body 'OK', got %q", resp.Text())
	}
}

func TestBrowserGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))
	defer server.Close()

	browser := NewBrowserTool()
	ctx := context.Background()
	resp, err := browser.Get(ctx, server.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestBrowserPost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"received": body,
		})
	}))
	defer server.Close()

	browser := NewBrowserTool()
	ctx := context.Background()
	payload := map[string]interface{}{"data": "test"}
	body, _ := json.Marshal(payload)

	resp, err := browser.Post(ctx, server.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Post failed: %v", err)
	}

	t.Logf("Response status: %d", resp.StatusCode)
}

func TestIsSuccess(t *testing.T) {
	tests := []struct {
		statusCode int
		expected   bool
	}{
		{200, true},
		{201, true},
		{204, true},
		{300, false},
		{400, false},
		{500, false},
	}

	for _, tt := range tests {
		resp := &Response{StatusCode: tt.statusCode}
		if resp.IsSuccess() != tt.expected {
			t.Errorf("Response{StatusCode: %d}.IsSuccess() = %v, want %v", tt.statusCode, !tt.expected, tt.expected)
		}
	}
}

func TestText(t *testing.T) {
	resp := &Response{Body: []byte("test body")}
	if resp.Text() != "test body" {
		t.Errorf("Text() = %q, want %q", resp.Text(), "test body")
	}
}

func TestJSON(t *testing.T) {
	resp := &Response{Body: []byte(`{"key": "value", "number": 123}`)}
	jsonResult, err := resp.JSON()
	if err != nil {
		t.Fatalf("JSON() failed: %v", err)
	}

	if jsonResult["key"] != "value" {
		t.Errorf("json[\"key\"] = %v, want %q", jsonResult["key"], "value")
	}
}

func TestFormatter(t *testing.T) {
	resp := &Response{
		StatusCode:    200,
		Headers:       http.Header{"Content-Type": []string{"application/json"}},
		Body:          []byte(`{"status": "ok"}`),
		URL:           "http://example.com/api",
		RequestMethod: "GET",
	}

	output := NewFormatter(2).FormatResponse(resp)
	if output == "" {
		t.Error("expected non-empty formatted output")
	}
	if !strings.Contains(output, "200") {
		t.Error("expected status code in output")
	}
	if !strings.Contains(output, "application/json") {
		t.Error("expected content-type in output")
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		rawURL   string
		expected bool
	}{
		{"https://example.com/path", true},
		{"http://localhost:8080", true},
		{"https://example.com:443", true},
		{"", false},
		{"://no-scheme.com", false},
		{"missing-scheme.com", false},
	}

	for _, tt := range tests {
		_, err := ValidateURL(tt.rawURL)
		if tt.expected && err != nil {
			t.Errorf("ValidateURL(%q) should have passed, got error: %v", tt.rawURL, err)
		}
		if !tt.expected && err == nil {
			t.Errorf("ValidateURL(%q) should have failed", tt.rawURL)
		}
	}
}

func TestWebhookTester(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()

	webhook := NewWebhookTester()
	ctx := context.Background()
	payload := map[string]interface{}{"event": "test", "data": "hello"}

	resp, err := webhook.SendTestRequest(ctx, server.URL, payload)
	if err != nil {
		t.Fatalf("SendTestRequest failed: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !strings.Contains(resp.Text(), "hello") {
		t.Logf("response body: %s", resp.Text())
	}
}

func TestWebhookTesterValidate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	webhook := NewWebhookTester()
	err := webhook.ValidateWebhook(context.Background(), server.URL, http.StatusOK)
	if err != nil {
		t.Errorf("expected webhook to pass, got error: %v", err)
	}
}
