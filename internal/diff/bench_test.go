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
