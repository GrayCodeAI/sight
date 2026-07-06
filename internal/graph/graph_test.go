package graph

import (
	"fmt"
	"testing"
)

func TestNew(t *testing.T) {
	g := New()
	if g == nil {
		t.Fatal("expected non-nil graph")
	}
	if len(g.nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(g.nodes))
	}
}

func TestAddNode(t *testing.T) {
	g := New()

	node := &Node{
		URI:  "file:///path/to/main.go",
		Name: "main.go",
		Type: NodeTypeFile,
	}

	g.AddNode(node)

	if len(g.nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(g.nodes))
	}

	got := g.nodes["file:///path/to/main.go"]
	if got != node {
		t.Error("expected same node reference")
	}
}

func TestAddEdge(t *testing.T) {
	g := New()

	g.AddEdge("file:///a.go", "type:///a.go/MyType", EdgeCalls)

	if len(g.edges) != 2 {
		t.Errorf("expected 2 edge entries, got %d", len(g.edges))
	}

	edges := g.edges["file:///a.go"]
	if len(edges) != 1 {
		t.Errorf("expected 1 edge target, got %d", len(edges))
	}
	if edges[0] != "type:///a.go/MyType" {
		t.Errorf("expected edge target to be type:///a.go/MyType, got %s", edges[0])
	}
}

func TestGetNode(t *testing.T) {
	g := New()

	node := &Node{
		URI:  "file:///main.go",
		Name: "main.go",
		Type: NodeTypeFile,
	}
	g.AddNode(node)

	got := g.GetNode("file:///main.go")
	if got != node {
		t.Error("expected same node reference")
	}

	got = g.GetNode("file:///nonexistent.go")
	if got != nil {
		t.Error("expected nil for non-existent node")
	}
}

func TestGetBlastRadius(t *testing.T) {
	g := New()

	// Setup: main.go -> helper.go -> db.go
	g.AddEdge("file:///main.go", "file:///helper.go", EdgeCalls)
	g.AddEdge("file:///helper.go", "file:///db.go", EdgeCalls)

	result := g.GetBlastRadius([]string{"file:///main.go"})

	if len(result.Files) == 0 {
		t.Fatal("expected at least main.go in blast radius")
	}

	t.Logf("Blast radius: %d files, score %.2f", len(result.Files), result.Score())
}

func TestGetDirectDependents(t *testing.T) {
	g := New()

	// a.go -> b.go, c.go
	g.AddEdge("file:///a.go", "file:///b.go", EdgeCalls)
	g.AddEdge("file:///a.go", "file:///c.go", EdgeCalls)

	dependents := g.GetDirectDependents("file:///a.go")
	if len(dependents) != 2 {
		t.Errorf("expected 2 direct dependents, got %d: %v", len(dependents), dependents)
	}
}

func TestGetAllDependents(t *testing.T) {
	g := New()

	// a.go -> b.go -> c.go
	g.AddEdge("file:///a.go", "file:///b.go", EdgeCalls)
	g.AddEdge("file:///b.go", "file:///c.go", EdgeCalls)

	dependents := g.GetAllDependents("file:///b.go")
	if len(dependents) != 1 {
		t.Errorf("expected 1 dependent, got %d: %v", len(dependents), dependents)
	}
	if dependents[0] != "file:///c.go" {
		t.Errorf("expected c.go, got %s", dependents[0])
	}
}

func TestNodeTypeString(t *testing.T) {
	tests := []struct {
		nodeType NodeType
		expected string
	}{
		{NodeTypeFile, "file"},
		{NodeTypePackage, "package"},
		{NodeTypeFunction, "function"},
		{NodeTypeMethod, "method"},
		{NodeTypeType, "type"},
		{NodeTypeStruct, "struct"},
		{NodeTypeInterface, "interface"},
		{NodeType(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.nodeType.String()
		if got != tt.expected {
			t.Errorf("NodeType(%d).String() = %q, want %q", tt.nodeType, got, tt.expected)
		}
	}
}

func BenchmarkGetBlastRadius(b *testing.B) {
	for i := 0; i < b.N; i++ {
		g := New()

		for j := 0; j < 100; j++ {
			fileURI := fmt.Sprintf("file:///pkg%d/file.go", j)
			g.AddNode(&Node{URI: fileURI, Name: fmt.Sprintf("file%d.go", j), Type: NodeTypeFile})
			for k := 0; k < 10; k++ {
				depURI := fmt.Sprintf("file:///pkg%d/dep%d.go", j, k)
				g.AddNode(&Node{URI: depURI, Name: fmt.Sprintf("dep%d.go", k), Type: NodeTypeFile})
				g.AddEdge(fileURI, depURI, EdgeCalls)
			}
		}

		files := make([]string, 100)
		for j := range files {
			files[j] = fmt.Sprintf("file:///pkg%d/file.go", j)
		}

		result := g.GetBlastRadius(files)
		if result == nil {
			b.Fatal("expected non-nil result")
		}
		_ = g // avoid unused variable
	}
}
