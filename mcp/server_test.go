package mcp

import (
	"context"
	"encoding/json"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/GrayCodeAI/sight"
)

type mockProvider struct {
	response string
	err      error
}

func (m *mockProvider) Chat(_ context.Context, _ []sight.Message, _ sight.ChatOpts) (*sight.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &sight.Response{Content: m.response, TokensUsed: 100}, nil
}

func TestHandleReview_EmptyDiff(t *testing.T) {
	s := New(&mockProvider{response: "[]"})
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{"diff": ""}

	result, err := s.handleReview(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// Should return error result for empty diff
	if result == nil {
		t.Fatal("expected result")
	}
}

func TestHandleReview_ValidDiff(t *testing.T) {
	mockResp := `[{"severity":"high","file":"main.go","line":10,"message":"SQL injection","fix":"use parameterized query","reasoning":"user input in query"}]`
	s := New(&mockProvider{response: mockResp})

	diff := `--- a/main.go
+++ b/main.go
@@ -8,0 +9,3 @@
+func query(input string) {
+    db.Exec("SELECT * FROM users WHERE name = '" + input + "'")
+}`

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{"diff": diff}

	result, err := s.handleReview(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}

	// Should be valid JSON in the text content
	for _, c := range result.Content {
		if tc, ok := c.(mcplib.TextContent); ok {
			var parsed interface{}
			if json.Unmarshal([]byte(tc.Text), &parsed) != nil {
				t.Fatal("expected valid JSON response")
			}
		}
	}
}

func TestHandleDescribe_ValidDiff(t *testing.T) {
	mockResp := `{"title":"Add query function","summary":"Adds a database query helper","change_type":"feature","risk":"high"}`
	s := New(&mockProvider{response: mockResp})

	diff := `--- a/main.go
+++ b/main.go
@@ -1,0 +2,3 @@
+func hello() {
+    fmt.Println("hello")
+}`

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{"diff": diff}

	result, err := s.handleDescribe(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
}

func TestHandleImprove_ValidDiff(t *testing.T) {
	mockResp := `[{"file":"main.go","line":2,"category":"naming","description":"use camelCase","before":"my_func","after":"myFunc"}]`
	s := New(&mockProvider{response: mockResp})

	diff := `--- a/main.go
+++ b/main.go
@@ -1,0 +2,3 @@
+func my_func() {
+    return
+}`

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]interface{}{"diff": diff}

	result, err := s.handleImprove(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
}
