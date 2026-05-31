// Command sight is a small CLI around the sight library. Its primary purpose is
// to expose sight over the Model Context Protocol (MCP) and to run SSA-based
// cross-function taint analysis directly from the terminal.
//
// Usage:
//
//	sight mcp [--transport stdio|http] [--addr 127.0.0.1:8080]
//	sight taint [--path .] [--patterns ./...] [--json]
//
// The MCP server always exposes the sight_taint tool (no LLM required). The
// LLM-backed tools (sight_review/describe/improve) require a provider, which is
// supplied by an embedding host such as hawk; when run standalone they return a
// "no provider configured" error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/GrayCodeAI/sight"
	sightmcp "github.com/GrayCodeAI/sight/mcp"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "mcp":
		runMCP(os.Args[2:])
	case "taint":
		runTaint(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "sight: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sight - code review and taint analysis

Commands:
  mcp     Start the sight MCP server (stdio or http transport)
  taint   Run SSA cross-function taint analysis on Go packages

Run "sight <command> -h" for command-specific flags.
`)
}

func runMCP(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	transport := fs.String("transport", "stdio", "transport: stdio or http")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address for http transport")
	_ = fs.Parse(args)

	// nil provider: the sight_taint tool works without an LLM; the review tools
	// return a "no provider configured" error until a host wires one in.
	srv := sightmcp.New(nil)

	switch *transport {
	case "stdio":
		if err := srv.ServeStdio(); err != nil {
			fatal("serve stdio: %v", err)
		}
	case "http":
		fmt.Fprintf(os.Stderr, "sight mcp listening on http://%s/mcp\n", *addr)
		if err := srv.ServeHTTP(*addr); err != nil {
			fatal("serve http: %v", err)
		}
	default:
		fatal("unknown transport %q (want stdio or http)", *transport)
	}
}

func runTaint(args []string) {
	fs := flag.NewFlagSet("taint", flag.ExitOnError)
	path := fs.String("path", ".", "module/directory to analyze")
	patternsCSV := fs.String("patterns", "./...", "comma-separated go package patterns")
	asJSON := fs.Bool("json", false, "emit findings as JSON")
	_ = fs.Parse(args)

	var patterns []string
	for _, p := range strings.Split(*patternsCSV, ",") {
		if p = strings.TrimSpace(p); p != "" {
			patterns = append(patterns, p)
		}
	}

	analyzer := sight.NewSSATaintAnalyzer()
	findings, err := analyzer.AnalyzePackages(*path, patterns...)
	if err != nil {
		fatal("taint analysis: %v", err)
	}

	if *asJSON {
		b, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Println(string(b))
	} else {
		for _, f := range findings {
			fmt.Printf("[%s] %s:%d %s\n", f.Severity, f.File, f.Line, f.Message)
		}
		fmt.Printf("\n%d finding(s)\n", len(findings))
	}
	// Non-zero exit when high/critical findings exist, for CI gating.
	for _, f := range findings {
		if f.Severity.AtLeast(sight.SeverityHigh) {
			os.Exit(1)
		}
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "sight: "+format+"\n", a...)
	os.Exit(1)
}
