package main

import (
	"context"
	"fmt"
	"log"

	"github.com/GrayCodeAI/sight"
)

type mockProvider struct{}

func (m *mockProvider) Chat(ctx context.Context, messages []sight.Message, opts sight.ChatOpts) (*sight.Response, error) {
	return &sight.Response{
		Content: "Code looks good. Consider adding error handling for edge cases.",
	}, nil
}

func main() {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -10,6 +10,10 @@ func main() {
 	if err != nil {
 		log.Fatal(err)
 	}
+
+	// Process the data
+	processData(result)
+
 	fmt.Println("Done")
 }
`

	reviewer := sight.NewReviewer(
		sight.WithProvider(&mockProvider{}),
		sight.Thorough,
	)

	result, err := reviewer.Review(context.Background(), diff)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d findings:\n", len(result.Findings))
	for _, f := range result.Findings {
		fmt.Printf("[%s] %s:%d - %s\n", f.Severity, f.File, f.Line, f.Message)
	}
}
