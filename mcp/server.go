package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/GrayCodeAI/sight"
)

// Server wraps the sight library as an MCP server, exposing code review
// capabilities to any MCP-compatible agent.
type Server struct {
	server   *mcpserver.MCPServer
	provider sight.Provider
	opts     []sight.Option
}

// New creates a sight MCP server with the given LLM provider and options.
func New(provider sight.Provider, opts ...sight.Option) *Server {
	s := &Server{
		provider: provider,
		opts:     opts,
	}
	s.server = mcpserver.NewMCPServer(
		"sight", "0.2.0",
		mcpserver.WithToolCapabilities(true),
	)
	s.registerTools()
	return s
}

// ServeStdio starts the MCP server on stdin/stdout.
func (s *Server) ServeStdio() error {
	stdio := mcpserver.NewStdioServer(s.server)
	return stdio.Listen(context.Background(), os.Stdin, os.Stdout)
}

func (s *Server) registerTools() {
	s.server.AddTool(mcplib.NewTool(
		"sight_review",
		mcplib.WithDescription("Run AI code review on a unified diff"),
		mcplib.WithString("diff", mcplib.Required(), mcplib.Description("Unified diff text to review")),
	), s.handleReview)

	s.server.AddTool(mcplib.NewTool(
		"sight_describe",
		mcplib.WithDescription("Generate a PR description from a unified diff"),
		mcplib.WithString("diff", mcplib.Required(), mcplib.Description("Unified diff text")),
	), s.handleDescribe)

	s.server.AddTool(mcplib.NewTool(
		"sight_improve",
		mcplib.WithDescription("Suggest code improvements (non-bug focused)"),
		mcplib.WithString("diff", mcplib.Required(), mcplib.Description("Unified diff text")),
	), s.handleImprove)
}

func (s *Server) handleReview(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	diff := strArg(req, "diff")
	if diff == "" {
		return mcplib.NewToolResultError("diff is required"), nil
	}

	opts := append([]sight.Option{sight.WithProvider(s.provider)}, s.opts...)
	result, err := sight.Review(ctx, diff, opts...)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("review failed: %v", err)), nil
	}

	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, err
	}
	return mcplib.NewToolResultText(string(b)), nil
}

func (s *Server) handleDescribe(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	diff := strArg(req, "diff")
	if diff == "" {
		return mcplib.NewToolResultError("diff is required"), nil
	}

	opts := append([]sight.Option{sight.WithProvider(s.provider)}, s.opts...)
	desc, err := sight.Describe(ctx, diff, opts...)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("describe failed: %v", err)), nil
	}

	b, err := json.MarshalIndent(desc, "", "  ")
	if err != nil {
		return nil, err
	}
	return mcplib.NewToolResultText(string(b)), nil
}

func (s *Server) handleImprove(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	diff := strArg(req, "diff")
	if diff == "" {
		return mcplib.NewToolResultError("diff is required"), nil
	}

	opts := append([]sight.Option{sight.WithProvider(s.provider)}, s.opts...)
	result, err := sight.Improve(ctx, diff, opts...)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("improve failed: %v", err)), nil
	}

	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, err
	}
	return mcplib.NewToolResultText(string(b)), nil
}

func strArg(req mcplib.CallToolRequest, key string) string {
	if v, ok := req.GetArguments()[key].(string); ok {
		return v
	}
	return ""
}
