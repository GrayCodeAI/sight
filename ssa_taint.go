package sight

import (
	"fmt"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// SSATaintAnalyzer performs inter-procedural (cross-function) taint analysis on
// Go packages using the SSA intermediate representation. Unlike TaintAnalyzer
// (which is regex/diff-based and resets at every function boundary), this
// analyzer follows tainted values across call boundaries: when a tainted value
// is passed as an argument to a function, the corresponding parameter becomes
// tainted inside the callee, so a source in one function reaching a sink in
// another is detected.
type SSATaintAnalyzer struct {
	// MaxFindings caps the number of findings returned (0 = unlimited).
	MaxFindings int
	// Env, when non-nil, overrides the environment used to load packages
	// (e.g. append "GOWORK=off" to ignore a parent workspace). Nil inherits the
	// process environment.
	Env []string
}

// NewSSATaintAnalyzer creates an analyzer with default settings.
func NewSSATaintAnalyzer() *SSATaintAnalyzer {
	return &SSATaintAnalyzer{}
}

// AnalyzePackages loads the Go packages matched by the given patterns (e.g.
// "./...", "./internal/handlers") rooted at dir, builds SSA, and reports
// cross-function taint flows as Findings. A non-nil error is returned only for
// load failures; per-package type errors are tolerated where possible.
func (a *SSATaintAnalyzer) AnalyzePackages(dir string, patterns ...string) ([]Finding, error) {
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo,
		Dir:   dir,
		Tests: false,
	}
	if a.Env != nil {
		cfg.Env = a.Env
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, fmt.Errorf("sight: load packages: %w", err)
	}
	if len(pkgs) == 0 {
		return nil, nil
	}

	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	// Only descend (taint parameters) into functions belonging to the analyzed
	// packages, not the entire transitive stdlib, to keep analysis focused.
	initial := make(map[*types.Package]bool)
	for _, sp := range ssaPkgs {
		if sp != nil {
			initial[sp.Pkg] = true
		}
	}

	eng := &taintEngine{
		prog:     prog,
		fset:     prog.Fset,
		initial:  initial,
		tainted:  make(map[ssa.Value]string),
		seen:     make(map[ssa.Value]bool),
		findings: make(map[string]Finding),
	}
	eng.run()

	out := make([]Finding, 0, len(eng.findings))
	for _, f := range eng.findings {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	if a.MaxFindings > 0 && len(out) > a.MaxFindings {
		out = out[:a.MaxFindings]
	}
	return out, nil
}

// taintEngine holds the worklist state for one analysis run.
type taintEngine struct {
	prog    *ssa.Program
	fset    *token.FileSet
	initial map[*types.Package]bool

	tainted  map[ssa.Value]string // value -> source description
	seen     map[ssa.Value]bool
	worklist []ssa.Value

	findings map[string]Finding // dedup key -> finding
}

func (e *taintEngine) run() {
	funcs := ssautil.AllFunctions(e.prog)

	// Seed sources from functions in the analyzed packages.
	for fn := range funcs {
		if fn.Pkg == nil || !e.initial[fn.Pkg.Pkg] {
			continue
		}
		e.seedSources(fn)
	}

	// Fixed-point propagation.
	for len(e.worklist) > 0 {
		v := e.worklist[len(e.worklist)-1]
		e.worklist = e.worklist[:len(e.worklist)-1]
		e.propagate(v)
	}
}

// seedSources marks source values (parameters carrying untrusted input and
// results of source calls) as tainted.
func (e *taintEngine) seedSources(fn *ssa.Function) {
	// Untrusted request parameters.
	for _, p := range fn.Params {
		if isRequestType(p.Type()) {
			e.taint(p, "http.Request parameter")
		}
	}
	// Source calls (os.Getenv, r.FormValue, flag.String, ...).
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			if name, ok := sourceCallee(call.Common()); ok {
				e.taint(call, name)
			}
		}
	}
}

// taint marks v tainted with the given source description and enqueues it.
func (e *taintEngine) taint(v ssa.Value, source string) {
	if v == nil {
		return
	}
	if _, ok := e.tainted[v]; ok {
		return
	}
	e.tainted[v] = source
	e.worklist = append(e.worklist, v)
}

// propagate follows the def-use edges of a tainted value, spreading taint to
// derived values, into callee parameters, and into sinks.
func (e *taintEngine) propagate(v ssa.Value) {
	if e.seen[v] {
		return
	}
	e.seen[v] = true
	source := e.tainted[v]

	refs := v.Referrers()
	if refs == nil {
		return
	}
	for _, instr := range *refs {
		switch t := instr.(type) {
		case *ssa.Call:
			e.handleCall(v, source, t.Common(), t)
		case *ssa.Go:
			e.handleCall(v, source, t.Common(), t)
		case *ssa.Defer:
			e.handleCall(v, source, t.Common(), t)
		case *ssa.Store:
			// Tainting a memory cell taints subsequent loads of its address.
			if t.Val == v {
				e.taint(t.Addr, source)
				// Storing into an element/field taints the enclosing aggregate
				// so taint flows through the slice/struct (e.g. variadic args
				// packed into a slice for exec.Command).
				switch ad := t.Addr.(type) {
				case *ssa.IndexAddr:
					e.taint(ad.X, source)
				case *ssa.FieldAddr:
					e.taint(ad.X, source)
				}
			}
		case ssa.Value:
			// Pass-through SSA operations propagate taint to their result.
			if isPassThrough(instr) {
				e.taint(t, source)
			}
		}
	}
}

// handleCall processes a call instruction in which v appears (possibly as an
// argument): sinks are reported, sanitizers stop propagation, pass-through
// stdlib helpers propagate to the result, and user functions taint the matching
// parameter for cross-function flow.
func (e *taintEngine) handleCall(v ssa.Value, source string, c *ssa.CallCommon, instr ssa.Instruction) {
	argIdx := -1
	for i, a := range c.Args {
		if a == v {
			argIdx = i
			break
		}
	}
	if argIdx < 0 {
		return // v is the callee/closure, not an argument
	}

	// Sanitizers neutralize taint.
	if sanitizerCallee(c) {
		return
	}

	// Sinks: tainted data reaching a dangerous operation.
	if sink, ok := sinkCallee(c); ok {
		e.report(instr, source, sink)
		return
	}

	// Pass-through stdlib helpers (fmt.Sprintf, strings.Join, ...) yield tainted
	// results.
	if callValue, isVal := instr.(ssa.Value); isVal && passThroughCallee(c) {
		e.taint(callValue, source)
		return
	}

	// Cross-function: taint the callee parameter so sinks inside the callee are
	// found. Only descend into analyzed-package functions with a body.
	if fn := c.StaticCallee(); fn != nil && fn.Pkg != nil && e.initial[fn.Pkg.Pkg] && len(fn.Blocks) > 0 {
		pi := argIdx
		// Method calls carry the receiver as Params[0]; CallCommon.Args already
		// includes the receiver for invoke-mode, so indices line up.
		if pi < len(fn.Params) {
			e.taint(fn.Params[pi], source)
		}
	}
}

// report records a finding for a tainted value reaching a sink.
func (e *taintEngine) report(instr ssa.Instruction, source string, s sinkInfo) {
	pos := e.fset.Position(instr.Pos())
	file := pos.Filename
	line := pos.Line
	key := fmt.Sprintf("%s:%d:%s", file, line, s.kind)
	if _, ok := e.findings[key]; ok {
		return
	}
	e.findings[key] = Finding{
		Concern:    "taint:ssa-data-flow",
		Severity:   ParseSeverity(s.severity),
		File:       file,
		Line:       line,
		Message:    fmt.Sprintf("[SSA-TAINT-%s] untrusted data from %s reaches %s across function boundaries without sanitization", s.kind, source, s.name),
		Fix:        s.fix,
		CWE:        s.cwe,
		Confidence: 0.8,
		SASTSource: true,
	}
}

// ---------------------------------------------------------------------------
// Callee classification
// ---------------------------------------------------------------------------

func calleeString(c *ssa.CallCommon) string {
	if c.IsInvoke() {
		return c.Method.FullName()
	}
	if fn := c.StaticCallee(); fn != nil {
		return fn.String()
	}
	if c.Value != nil {
		return c.Value.String()
	}
	return ""
}

// sourceCallee reports whether a call produces untrusted data.
func sourceCallee(c *ssa.CallCommon) (string, bool) {
	name := calleeString(c)
	switch {
	case strings.HasSuffix(name, "os.Getenv"):
		return "os.Getenv", true
	case strings.Contains(name, "net/http.Request).FormValue"),
		strings.Contains(name, "net/http.Request).PostFormValue"),
		strings.Contains(name, "net/http.Request).Query"),
		strings.Contains(name, "net/http.Header).Get"):
		return "HTTP request input", true
	case strings.Contains(name, "net/url.Values).Get"):
		return "URL query value", true
	case strings.HasPrefix(name, "flag.") && name != "flag.Parse":
		return "command-line flag", true
	}
	return "", false
}

type sinkInfo struct {
	name     string
	kind     string
	cwe      string
	severity string
	fix      string
}

// sinkCallee reports whether a call is a security-sensitive sink.
func sinkCallee(c *ssa.CallCommon) (sinkInfo, bool) {
	name := calleeString(c)
	switch {
	case matchesSQL(name):
		return sinkInfo{
			"SQL query execution", "SQL_INJECTION", "CWE-89", "critical",
			"Use parameterized queries (db.Query(sql, args...)) instead of string concatenation",
		}, true
	case strings.Contains(name, "os/exec.Command"), strings.Contains(name, "os/exec.CommandContext"):
		return sinkInfo{
			"command execution", "COMMAND_INJECTION", "CWE-78", "critical",
			"Avoid passing untrusted input to exec.Command; use an allowlist",
		}, true
	case matchesFileOp(name):
		return sinkInfo{
			"file operation", "PATH_TRAVERSAL", "CWE-22", "high",
			"Use filepath.Clean and confirm the path stays within an allowed root",
		}, true
	case strings.Contains(name, "text/template.Template).Execute"):
		return sinkInfo{
			"template execution", "XSS", "CWE-79", "high",
			"Use html/template for HTML output to auto-escape untrusted data",
		}, true
	case strings.Contains(name, "net/http.ResponseWriter") && strings.Contains(name, "Write"):
		return sinkInfo{
			"HTTP response write", "XSS", "CWE-79", "high",
			"Escape untrusted data before writing it to an HTTP response",
		}, true
	}
	return sinkInfo{}, false
}

func matchesSQL(name string) bool {
	if !strings.Contains(name, "database/sql") {
		return false
	}
	for _, m := range []string{").Query", ").QueryRow", ").QueryContext", ").QueryRowContext", ").Exec", ").ExecContext"} {
		if strings.Contains(name, m) {
			return true
		}
	}
	return false
}

func matchesFileOp(name string) bool {
	for _, m := range []string{"os.Open", "os.Create", "os.ReadFile", "os.WriteFile", "os.OpenFile", "os.Remove", "os.MkdirAll"} {
		if strings.HasSuffix(name, m) {
			return true
		}
	}
	return false
}

// sanitizerCallee reports whether a call cleans tainted data.
func sanitizerCallee(c *ssa.CallCommon) bool {
	name := calleeString(c)
	for _, s := range []string{
		"path/filepath.Clean", "net/url.QueryEscape", "net/url.PathEscape",
		"html.EscapeString", "html/template.HTMLEscapeString", "strconv.Quote",
		"strconv.Atoi", "strconv.ParseInt",
	} {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// passThroughCallee reports whether a call forwards taint from its arguments to
// its result (string-building helpers).
func passThroughCallee(c *ssa.CallCommon) bool {
	name := calleeString(c)
	for _, s := range []string{
		"fmt.Sprintf", "fmt.Sprint", "fmt.Sprintln",
		"strings.Join", "strings.TrimSpace", "strings.ToLower", "strings.ToUpper",
		"strings.ReplaceAll", "strings.TrimPrefix", "strings.TrimSuffix",
	} {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// isPassThrough reports whether an SSA instruction forwards taint from its
// operands to its result value.
func isPassThrough(instr ssa.Instruction) bool {
	switch instr.(type) {
	case *ssa.BinOp, // string concatenation and comparisons
		*ssa.Phi,
		*ssa.UnOp,    // pointer dereference / load
		*ssa.Convert, // type conversions
		*ssa.ChangeType,
		*ssa.ChangeInterface,
		*ssa.MakeInterface,
		*ssa.Slice,
		*ssa.Field,
		*ssa.FieldAddr,
		*ssa.Index,
		*ssa.IndexAddr,
		*ssa.Extract,
		*ssa.TypeAssert:
		return true
	}
	return false
}

// isRequestType reports whether t is *net/http.Request.
func isRequestType(t types.Type) bool {
	return strings.Contains(t.String(), "net/http.Request")
}
