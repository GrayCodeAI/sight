// Package graph provides structural dependency analysis for code reviews.
// It builds and queries a graph of code units to identify blast-radius
// impacts and minimal review sets.
package graph

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Node represents a code unit in the dependency graph.
type Node struct {
	URI  string
	Name string
	Type NodeType
}

// NodeType represents the type of node.
type NodeType int

const (
	NodeTypeFunction NodeType = iota
	NodeTypeMethod
	NodeTypeType
	NodeTypeStruct
	NodeTypeInterface
	NodeTypePackage
	NodeTypeFile
)

// String returns a string representation of the node type.
func (n NodeType) String() string {
	switch n {
	case NodeTypeFunction:
		return "function"
	case NodeTypeMethod:
		return "method"
	case NodeTypeType:
		return "type"
	case NodeTypeStruct:
		return "struct"
	case NodeTypeInterface:
		return "interface"
	case NodeTypePackage:
		return "package"
	case NodeTypeFile:
		return "file"
	default:
		return "unknown"
	}
}

// EdgeType represents the type of dependency between nodes.
type EdgeType int

const (
	EdgeCalls EdgeType = iota
	EdgeReturns
	EdgeParameter
	EdgeReceiver
	EdgeImport
)

// String returns a string representation of the edge type.
func (e EdgeType) String() string {
	switch e {
	case EdgeCalls:
		return "calls"
	default:
		return "unknown"
	}
}

// BlastRadiusResult represents the results of a blast-radius analysis.
type BlastRadiusResult struct {
	Files       []string `json:"files"`
	Direct      int      `json:"direct"`
	Transitive  int      `json:"transitive"`
	MaxDepth    int      `json:"max_depth"`
	ImpactScore float64  `json:"impact_score"`
}

// Score computes an overall impact score.
func (b *BlastRadiusResult) Score() float64 {
	if len(b.Files) == 0 {
		return 0
	}
	score := 0.0
	for i := range b.Files {
		if i < b.Direct {
			score += 1.0
		} else {
			depth := b.MaxDepth - int(float64(b.MaxDepth)*(float64(i)/float64(len(b.Files))))
			switch {
			case depth == 2:
				score += 0.8
			case depth == 3:
				score += 0.6
			case depth == 4:
				score += 0.4
			default:
				score += 0.2
			}
		}
	}
	return score / float64(len(b.Files))
}

// DependencyGraph represents structural dependencies between code units.
type DependencyGraph struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	edges map[string][]string
}

// New creates a new DependencyGraph.
func New() *DependencyGraph {
	return &DependencyGraph{
		nodes: make(map[string]*Node),
		edges: make(map[string][]string),
	}
}

// AddNode adds a node to the graph.
func (g *DependencyGraph) AddNode(node *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[node.URI] = node
}

// AddEdge adds a dependency edge between two nodes.
func (g *DependencyGraph) AddEdge(from, to string, _ EdgeType) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.edges[from] == nil {
		g.edges[from] = []string{}
	}
	for _, target := range g.edges[from] {
		if target == to {
			return
		}
	}
	g.edges[from] = append(g.edges[from], to)

	if g.edges[to] == nil {
		g.edges[to] = []string{}
	}
}

// GetNode returns a node by URI.
func (g *DependencyGraph) GetNode(uri string) *Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.nodes[uri]
}

// GetDirectDependents returns direct dependents (outgoing edges).
func (g *DependencyGraph) GetDirectDependents(uri string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.edges[uri]
}

// GetAllDependents returns all transitive dependents.
func (g *DependencyGraph) GetAllDependents(uri string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	visited := make(map[string]bool)
	var result []string
	var traverse func(n string)
	traverse = func(n string) {
		if visited[n] {
			return
		}
		visited[n] = true
		for _, child := range g.edges[n] {
			result = append(result, child)
			traverse(child)
		}
	}
	traverse(uri)
	return result
}

// Build parses a Go module and builds the dependency graph.
func (g *DependencyGraph) Build(ctx context.Context, modulePath string) error {
	start := time.Now()

	fset := token.NewFileSet()
	packages, err := parser.ParseDir(fset, modulePath, nil, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("failed to parse module %s: %w", modulePath, err)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for pkgName, pkg := range packages {
		pkgURI := fmt.Sprintf("pkg://%s", pkgName)
		g.AddNode(&Node{URI: pkgURI, Name: pkgName, Type: NodeTypePackage})

		for filename, f := range pkg.Files {
			fileURI := fmt.Sprintf("file://%s", filename)
			g.AddNode(&Node{URI: fileURI, Name: filepath.Base(filename), Type: NodeTypeFile})
			g.AddEdge(pkgURI, fileURI, EdgeCalls)

			for _, decl := range f.Decls {
				wg.Add(1)
				sem <- struct{}{}
				go func(d ast.Decl, fURI string) {
					defer func() { <-sem }()
					defer wg.Done()
					g.processDecl(d, fURI)
				}(decl, fileURI)
			}
		}
	}

	wg.Wait()
	close(sem)
	fmt.Printf("Graph built in %v\n", time.Since(start))
	return nil
}

// processDecl processes an AST declaration.
func (g *DependencyGraph) processDecl(decl ast.Decl, fileURI string) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		g.processFuncDecl(d, fileURI)
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			if ts, ok := spec.(*ast.TypeSpec); ok {
				g.processTypeSpec(ts, fileURI)
			}
		}
	}
}

// processFuncDecl processes a function declaration.
func (g *DependencyGraph) processFuncDecl(d *ast.FuncDecl, fileURI string) {
	funcName := d.Name.Name
	methodName := funcName
	typName := ""

	if d.Recv != nil {
		for _, r := range d.Recv.List {
			if ident, ok := r.Type.(*ast.Ident); ok {
				typName = ident.Name
			}
		}
		methodName = fmt.Sprintf("%s.%s", typName, funcName)
	}

	methodURI := fmt.Sprintf("method://%s/%s", fileURI, methodName)
	g.AddNode(&Node{URI: methodURI, Name: methodName, Type: NodeTypeMethod})
	g.AddEdge(fileURI, methodURI, EdgeCalls)

	if d.Body != nil {
		g.extractCalls(d.Body, methodURI)
	}
	g.extractReturns(d.Type, methodURI, methodName)
}

// processTypeSpec processes a type specification.
func (g *DependencyGraph) processTypeSpec(ts *ast.TypeSpec, fileURI string) {
	typeName := ts.Name.Name
	typeURI := fmt.Sprintf("type://%s/%s", fileURI, typeName)

	switch ts.Type.(type) {
	case *ast.StructType:
		g.AddNode(&Node{URI: typeURI, Name: typeName, Type: NodeTypeStruct})
	case *ast.InterfaceType:
		g.AddNode(&Node{URI: typeURI, Name: typeName, Type: NodeTypeInterface})
	default:
		g.AddNode(&Node{URI: typeURI, Name: typeName, Type: NodeTypeType})
	}

	g.AddEdge(fileURI, typeURI, EdgeCalls)

	if structType, ok := ts.Type.(*ast.StructType); ok {
		for _, field := range structType.Fields.List {
			if field.Names != nil {
				for _, name := range field.Names {
					embeddedURI := fmt.Sprintf("type://%s/%s", fileURI, name.Name)
					g.AddNode(&Node{URI: embeddedURI, Name: name.Name, Type: NodeTypeType})
					g.AddEdge(typeURI, embeddedURI, EdgeCalls)
				}
			} else if ident, ok := field.Type.(*ast.Ident); ok {
				embeddedURI := fmt.Sprintf("type://%s/%s", fileURI, ident.Name)
				g.AddNode(&Node{URI: embeddedURI, Name: ident.Name, Type: NodeTypeType})
				g.AddEdge(typeURI, embeddedURI, EdgeCalls)
			}
		}
	}
}

// extractCalls extracts function/method calls from a body.
func (g *DependencyGraph) extractCalls(body *ast.BlockStmt, fromURI string) {
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		callName := ""
		callType := NodeTypeFunction

		if ident, ok := call.Fun.(*ast.Ident); ok {
			callName = ident.Name
		} else if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			callName = sel.Sel.Name
			callType = NodeTypeMethod
		}

		if callName == "" {
			return true
		}

		callURI := fmt.Sprintf("func://%s/%s", fromURI, callName)
		g.AddNode(&Node{URI: callURI, Name: callName, Type: callType})
		g.AddEdge(fromURI, callURI, EdgeCalls)
		return true
	})
}

// extractReturns extracts return value dependencies.
func (g *DependencyGraph) extractReturns(t *ast.FuncType, fromURI, methodName string) {
	if t == nil || t.Results == nil {
		return
	}

	for _, field := range t.Results.List {
		for _, name := range field.Names {
			returnURI := fmt.Sprintf("return://%s/%s", fromURI, name.Name)
			g.AddNode(&Node{URI: returnURI, Name: name.Name, Type: NodeTypeFunction})
			g.AddEdge(fromURI, returnURI, EdgeCalls)
		}
	}
}

// GetBlastRadius returns files affected by changing the given files.
func (g *DependencyGraph) GetBlastRadius(files []string) *BlastRadiusResult {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := &BlastRadiusResult{
		Files:      make([]string, 0, len(files)*10),
		Direct:     len(files),
		Transitive: 0,
		MaxDepth:   0,
	}

	fileScores := make(map[string]float64)

	for _, file := range files {
		if g.nodes[file] == nil {
			continue
		}

		directDeps := g.edges[file]
		result.Transitive += len(directDeps)

		if len(directDeps) > 0 {
			result.MaxDepth = max(result.MaxDepth, 2)
		}

		for _, dep := range directDeps {
			if g.nodes[dep] == nil {
				continue
			}
			result.Files = append(result.Files, dep)
			fileScores[dep] += 0.8

			for _, transDep := range g.edges[dep] {
				if g.nodes[transDep] == nil {
					continue
				}
				fileScores[transDep] += 0.6
				result.MaxDepth = max(result.MaxDepth, 3)

				for _, grand := range g.edges[transDep] {
					if g.nodes[grand] == nil {
						continue
					}
					fileScores[grand] += 0.4
					result.MaxDepth = max(result.MaxDepth, 4)
				}
			}
		}
	}

	for _, file := range files {
		fileScores[file] = 1.0
	}
	for _, file := range files {
		result.Files = append(result.Files, file)
	}

	sortByScore(result.Files, fileScores)
	result.ImpactScore = result.Score()
	return result
}

func sortByScore(strs []string, scores map[string]float64) {
	sort.Slice(strs, func(i, j int) bool {
		return scores[strs[i]] > scores[strs[j]]
	})
}
