package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/GrayCodeAI/sight"
)

func callTaint(t *testing.T, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	s := New(nil) // taint tool needs no provider
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = args
	res, err := s.handleTaint(context.Background(), req)
	if err != nil {
		t.Fatalf("handleTaint: %v", err)
	}
	return res
}

func taintResultText(res *mcplib.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(mcplib.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestSightTaintTool_FindsCrossFunctionFlows(t *testing.T) {
	dir, err := filepath.Abs("../testdata/crossfunc")
	if err != nil {
		t.Fatal(err)
	}
	// Disable the workspace so the nested fixture module loads standalone.
	t.Setenv("GOWORK", "off")

	res := callTaint(t, map[string]any{"path": dir, "patterns": "."})
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", taintResultText(res))
	}

	var findings []sight.Finding
	if err := json.Unmarshal([]byte(taintResultText(res)), &findings); err != nil {
		t.Fatalf("decode findings: %v\n%s", err, taintResultText(res))
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings from sight_taint tool, got none")
	}

	var sawSQL bool
	for _, f := range findings {
		if strings.Contains(f.Message, "SQL_INJECTION") {
			sawSQL = true
		}
	}
	if !sawSQL {
		t.Errorf("expected a SQL_INJECTION finding via the MCP tool")
	}
}

func TestSightTaintTool_RequiresPath(t *testing.T) {
	res := callTaint(t, map[string]any{})
	if !res.IsError {
		t.Errorf("expected error when path is missing")
	}
}
