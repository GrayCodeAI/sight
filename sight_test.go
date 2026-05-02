package sight_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/GrayCodeAI/sight"
)

// mockProvider implements sight.Provider for testing.
type mockProvider struct {
	response string
	err      error
	calls    int64
	mu       sync.Mutex
}

func (m *mockProvider) Chat(ctx context.Context, messages []sight.Message, opts sight.ChatOpts) (*sight.Response, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	return &sight.Response{
		Content:    m.response,
		TokensUsed: 500,
	}, nil
}

func (m *mockProvider) getCalls() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

const testDiff = `diff --git a/handler.go b/handler.go
index abc1234..def5678 100644
--- a/handler.go
+++ b/handler.go
@@ -10,6 +10,10 @@ func handleRequest(w http.ResponseWriter, r *http.Request) {
 	userID := r.URL.Query().Get("id")

-	user, err := db.GetUser(userID)
+	query := "SELECT * FROM users WHERE id = '" + userID + "'"
+	user, err := db.RawQuery(query)
+	if err != nil {
+		log.Printf("Error: %v, query: %s", err, query)
+	}

 	json.NewEncoder(w).Encode(user)
 }
`

func mockFindings() string {
	findings := []struct {
		File      string `json:"file"`
		Line      int    `json:"line"`
		EndLine   int    `json:"end_line"`
		Severity  string `json:"severity"`
		Message   string `json:"message"`
		Fix       string `json:"fix"`
		Reasoning string `json:"reasoning"`
	}{
		{
			File:      "handler.go",
			Line:      13,
			EndLine:   14,
			Severity:  "critical",
			Message:   "SQL injection via string concatenation",
			Fix:       `query := "SELECT * FROM users WHERE id = $1"\nuser, err := db.Query(query, userID)`,
			Reasoning: "User input directly concatenated into SQL allows arbitrary query execution",
		},
		{
			File:      "handler.go",
			Line:      15,
			Severity:  "high",
			Message:   "SQL query logged with user data, potential information disclosure",
			Fix:       `log.Printf("Error fetching user: %v", err)`,
			Reasoning: "Logging raw SQL queries can expose sensitive data in log aggregators",
		},
	}
	out, _ := json.Marshal(findings)
	return string(out)
}

func TestReview_Basic(t *testing.T) {
	provider := &mockProvider{response: mockFindings()}

	result, err := sight.Review(context.Background(), testDiff,
		sight.WithProvider(provider),
		sight.WithConcerns("security"),
		sight.WithParallel(false),
	)
	if err != nil {
		t.Fatalf("Review failed: %v", err)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}

	if result.Findings[0].Severity != sight.SeverityCritical {
		t.Errorf("expected critical severity, got %v", result.Findings[0].Severity)
	}
	if result.Findings[0].File != "handler.go" {
		t.Errorf("expected handler.go, got %s", result.Findings[0].File)
	}
	if result.Stats.FilesReviewed != 1 {
		t.Errorf("expected 1 file reviewed, got %d", result.Stats.FilesReviewed)
	}
	if result.Stats.TokensUsed != 500 {
		t.Errorf("expected 500 tokens used, got %d", result.Stats.TokensUsed)
	}
}

func TestReview_MultipleConcerns(t *testing.T) {
	provider := &mockProvider{response: mockFindings()}

	result, err := sight.Review(context.Background(), testDiff,
		sight.WithProvider(provider),
		sight.WithConcerns("security", "bugs"),
		sight.WithParallel(true),
	)
	if err != nil {
		t.Fatalf("Review failed: %v", err)
	}

	if provider.getCalls() != 2 {
		t.Errorf("expected 2 provider calls (one per concern), got %d", provider.getCalls())
	}

	if result.Stats.TokensUsed != 1000 {
		t.Errorf("expected 1000 tokens (500 per call), got %d", result.Stats.TokensUsed)
	}
}

func TestReview_NoProvider(t *testing.T) {
	_, err := sight.Review(context.Background(), testDiff)
	if err != sight.ErrNoProvider {
		t.Errorf("expected ErrNoProvider, got %v", err)
	}
}

func TestReview_EmptyDiff(t *testing.T) {
	provider := &mockProvider{response: "[]"}
	_, err := sight.Review(context.Background(), "",
		sight.WithProvider(provider),
	)
	if err != sight.ErrEmptyDiff {
		t.Errorf("expected ErrEmptyDiff, got %v", err)
	}
}

func TestReview_ProviderError(t *testing.T) {
	provider := &mockProvider{err: fmt.Errorf("rate limited")}

	result, err := sight.Review(context.Background(), testDiff,
		sight.WithProvider(provider),
		sight.WithConcerns("security"),
		sight.WithParallel(false),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings on provider error, got %d", len(result.Findings))
	}
}

func TestResult_Failed(t *testing.T) {
	r := &sight.Result{
		FailOn: sight.SeverityHigh,
		Findings: []sight.Finding{
			{Severity: sight.SeverityLow, Message: "minor"},
		},
	}
	if r.Failed() {
		t.Error("should not fail on low finding when threshold is high")
	}

	r.Findings = append(r.Findings, sight.Finding{
		Severity: sight.SeverityHigh, Message: "major",
	})
	if !r.Failed() {
		t.Error("should fail when finding meets threshold")
	}
}

func TestResult_MaxSeverity(t *testing.T) {
	r := &sight.Result{
		Findings: []sight.Finding{
			{Severity: sight.SeverityLow},
			{Severity: sight.SeverityCritical},
			{Severity: sight.SeverityMedium},
		},
	}
	if r.MaxSeverity() != sight.SeverityCritical {
		t.Errorf("expected critical, got %v", r.MaxSeverity())
	}
}

func TestReview_Presets(t *testing.T) {
	provider := &mockProvider{response: "[]"}

	presets := []sight.Option{sight.Quick, sight.Thorough, sight.SecurityFocus, sight.CI}
	for _, preset := range presets {
		_, err := sight.Review(context.Background(), testDiff,
			sight.WithProvider(provider),
			preset,
		)
		if err != nil {
			t.Errorf("preset review failed: %v", err)
		}
	}
}

func TestReview_Deduplication(t *testing.T) {
	// Same finding from two concerns should be deduped
	response := `[{"file": "handler.go", "line": 13, "severity": "high", "message": "SQL injection", "fix": "use params"}]`
	provider := &mockProvider{response: response}

	result, err := sight.Review(context.Background(), testDiff,
		sight.WithProvider(provider),
		sight.WithConcerns("security", "bugs"),
		sight.WithParallel(false),
	)
	if err != nil {
		t.Fatalf("Review failed: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(result.Findings))
	}
}
