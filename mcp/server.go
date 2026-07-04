package mcp

import (
	"context"
	"fmt"
	"strings"

	mcpkit "github.com/GrayCodeAI/hawk-mcpkit"
	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/GrayCodeAI/sight"
)

// Server wraps the sight library as an MCP server, exposing code review
// capabilities to any MCP-compatible agent.
type Server struct {
	kit      *mcpkit.Server
	provider sight.Provider
	opts     []sight.Option
}

// New creates a sight MCP server with the given LLM provider and options.
func New(provider sight.Provider, opts ...sight.Option) *Server {
	s := &Server{
		kit:      mcpkit.New("sight", sight.Version),
		provider: provider,
		opts:     opts,
	}
	s.registerTools()
	return s
}

// ServeStdio starts the MCP server on stdin/stdout.
func (s *Server) ServeStdio() error {
	return s.kit.ServeStdio()
}

// ServeHTTP starts the MCP server on a streamable HTTP endpoint. Clients
// connect to http://<addr>/mcp.
func (s *Server) ServeHTTP(addr string) error {
	return s.kit.ServeHTTP(addr)
}

func (s *Server) registerTools() {
	s.kit.AddTool(mcplib.NewTool(
		"sight_review",
		mcplib.WithDescription("Run AI code review on a unified diff"),
		mcplib.WithString("diff", mcplib.Required(), mcplib.Description("Unified diff text to review")),
	), s.handleReview)

	s.kit.AddTool(mcplib.NewTool(
		"sight_describe",
		mcplib.WithDescription("Generate a PR description from a unified diff"),
		mcplib.WithString("diff", mcplib.Required(), mcplib.Description("Unified diff text")),
	), s.handleDescribe)

	s.kit.AddTool(mcplib.NewTool(
		"sight_improve",
		mcplib.WithDescription("Suggest code improvements (non-bug focused)"),
		mcplib.WithString("diff", mcplib.Required(), mcplib.Description("Unified diff text")),
	), s.handleImprove)

	s.kit.AddTool(mcplib.NewTool(
		"sight_taint",
		mcplib.WithDescription("Run SSA-based cross-function taint analysis on Go packages and return security findings (no LLM required)"),
		mcplib.WithString("path", mcplib.Required(), mcplib.Description("Filesystem path to the module/directory to analyze")),
		mcplib.WithString("patterns", mcplib.Description("Comma-separated go package patterns to load (default \"./...\")")),
	), s.handleTaint)
}

func (s *Server) handleTaint(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	path := mcpkit.StrArg(req, "path")
	if path == "" {
		return mcplib.NewToolResultError("path is required"), nil
	}
	var patterns []string
	if p := mcpkit.StrArg(req, "patterns"); p != "" {
		for _, part := range strings.Split(p, ",") {
			if part = strings.TrimSpace(part); part != "" {
				patterns = append(patterns, part)
			}
		}
	}

	analyzer := sight.NewSSATaintAnalyzer()
	findings, err := analyzer.AnalyzePackages(path, patterns...)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("taint analysis failed: %v", err)), nil
	}
	return mcpkit.JSONResult(findings)
}

func (s *Server) handleReview(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	diff := mcpkit.StrArg(req, "diff")
	if diff == "" {
		return mcplib.NewToolResultError("diff is required"), nil
	}

	opts := append([]sight.Option{sight.WithProvider(s.provider)}, s.opts...)
	result, err := sight.Review(ctx, diff, opts...)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("review failed: %v", err)), nil
	}
	return mcpkit.JSONResult(result)
}

func (s *Server) handleDescribe(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	diff := mcpkit.StrArg(req, "diff")
	if diff == "" {
		return mcplib.NewToolResultError("diff is required"), nil
	}

	opts := append([]sight.Option{sight.WithProvider(s.provider)}, s.opts...)
	desc, err := sight.Describe(ctx, diff, opts...)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("describe failed: %v", err)), nil
	}
	return mcpkit.JSONResult(desc)
}

func (s *Server) handleImprove(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	diff := mcpkit.StrArg(req, "diff")
	if diff == "" {
		return mcplib.NewToolResultError("diff is required"), nil
	}

	opts := append([]sight.Option{sight.WithProvider(s.provider)}, s.opts...)
	result, err := sight.Improve(ctx, diff, opts...)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("improve failed: %v", err)), nil
	}
	return mcpkit.JSONResult(result)
}
