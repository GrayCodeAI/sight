package diff

import (
	"strings"
	"testing"
)

func generateLargeDiff(files, hunksPerFile, linesPerHunk int) string {
	var b strings.Builder
	for f := 0; f < files; f++ {
		b.WriteString("diff --git a/file")
		b.WriteString(string(rune('a' + f)))
		b.WriteString(".go b/file")
		b.WriteString(string(rune('a' + f)))
		b.WriteString(".go\n")
		b.WriteString("--- a/file")
		b.WriteString(string(rune('a' + f)))
		b.WriteString(".go\n")
		b.WriteString("+++ b/file")
		b.WriteString(string(rune('a' + f)))
		b.WriteString(".go\n")

		for h := 0; h < hunksPerFile; h++ {
			start := h*linesPerHunk + 1
			b.WriteString("@@ -")
			b.WriteString(itoa(start))
			b.WriteString(",")
			b.WriteString(itoa(linesPerHunk))
			b.WriteString(" +")
			b.WriteString(itoa(start))
			b.WriteString(",")
			b.WriteString(itoa(linesPerHunk + 2))
			b.WriteString(" @@ func example\n")

			for l := 0; l < linesPerHunk; l++ {
				if l%3 == 0 {
					b.WriteString("+\tnewLine := doSomething()\n")
				} else if l%5 == 0 {
					b.WriteString("-\toldLine := deprecated()\n")
				} else {
					b.WriteString(" \texistingCode()\n")
				}
			}
		}
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func BenchmarkParse_SmallDiff(b *testing.B) {
	diff := generateLargeDiff(1, 2, 10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Parse(diff)
	}
}

func BenchmarkParse_MediumDiff(b *testing.B) {
	diff := generateLargeDiff(5, 5, 30)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Parse(diff)
	}
}

func BenchmarkParse_LargeDiff(b *testing.B) {
	diff := generateLargeDiff(20, 10, 50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Parse(diff)
	}
}

func BenchmarkSummary(b *testing.B) {
	diff := generateLargeDiff(10, 5, 20)
	files := Parse(diff)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Summary(files)
	}
}

// BenchmarkParseDiff benchmarks parsing a realistic multi-file diff.
func BenchmarkParseDiff(b *testing.B) {
	const realisticDiff = `diff --git a/src/handler.go b/src/handler.go
index a1b2c3d..e4f5g6h 100644
--- a/src/handler.go
+++ b/src/handler.go
@@ -15,12 +15,18 @@ import (
 	"net/http"
 	"encoding/json"
+	"fmt"
+	"log"
 )

 // HandleRequest processes incoming API requests.
-func HandleRequest(w http.ResponseWriter, r *http.Request) {
-	var req Request
-	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
+func HandleRequest(w http.ResponseWriter, r *http.Request) error {
+	var req *Request
+	if r.Body == nil {
+		return fmt.Errorf("empty request body")
+	}
+	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
 		http.Error(w, err.Error(), http.StatusBadRequest)
-		return
+		return err
 	}
+	log.Printf("processing request: %s", req.ID)
 	respond(w, process(req))
+	return nil
 }
diff --git a/src/model.go b/src/model.go
index b2c3d4e..f5g6h7i 100644
--- a/src/model.go
+++ b/src/model.go
@@ -1,8 +1,12 @@
 package src

+import "time"
+
 type Request struct {
-	ID    string ` + "`" + `json:"id"` + "`" + `
-	Value int    ` + "`" + `json:"value"` + "`" + `
+	ID        string    ` + "`" + `json:"id"` + "`" + `
+	Value     int       ` + "`" + `json:"value"` + "`" + `
+	CreatedAt time.Time ` + "`" + `json:"created_at"` + "`" + `
+	UpdatedAt time.Time ` + "`" + `json:"updated_at"` + "`" + `
 }
 `
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Parse(realisticDiff)
	}
}

// BenchmarkParseHunkHeader benchmarks parsing a hunk header line.
func BenchmarkParseHunkHeader(b *testing.B) {
	benchmarks := []struct {
		name  string
		input string
	}{
		{"Simple", "@@ -1,3 +1,4 @@"},
		{"WithContext", "@@ -10,6 +10,8 @@ func main() {"},
		{"NewFile", "@@ -0,0 +1,25 @@ package main"},
		{"LargeNumbers", "@@ -999999,1000000 +999999,1000000 @@ func big() {"},
	}
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				parseHunkHeader(bm.input)
			}
		})
	}
}
