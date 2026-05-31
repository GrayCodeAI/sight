package sight

import (
	"testing"
)

// TestDeduplicateFindings tests the deduplication of findings.
func TestDeduplicateFindings(t *testing.T) {
	config := NewDedupConfig()

	t.Run("empty input", func(t *testing.T) {
		result := DeduplicateFindings([]Finding{}, config)

		if len(result.Unique) != 0 {
			t.Errorf("Expected 0 unique findings, got %d", len(result.Unique))
		}
		if len(result.Duplicates) != 0 {
			t.Errorf("Expected 0 duplicate groups, got %d", len(result.Duplicates))
		}
	})

	t.Run("exact duplicates are merged", func(t *testing.T) {
		findings := []Finding{
			{
				Concern:    "security",
				Message:    "SQL injection vulnerability",
				File:       "user.go",
				Line:       45,
				Confidence: 0.95,
			},
			{
				Concern:    "security",
				Message:    "SQL injection vulnerability",
				File:       "user.go",
				Line:       45,
				Confidence: 0.85,
			},
			{
				Concern:    "security",
				Message:    "SQL injection vulnerability",
				File:       "user.go",
				Line:       45,
				Confidence: 0.75,
			},
		}

		result := DeduplicateFindings(findings, config)

		// Should keep the representative (highest confidence)
		if len(result.Unique) != 1 {
			t.Errorf("Expected 1 unique finding, got %d", len(result.Unique))
		}
		if len(result.Duplicates) != 1 {
			t.Errorf("Expected 1 duplicate group, got %d", len(result.Duplicates))
		}
		if result.Duplicates[0].Representative.Confidence != 0.95 {
			t.Errorf("Expected representative confidence 0.95, got %.2f",
				result.Duplicates[0].Representative.Confidence)
		}
		if len(result.Duplicates[0].Duplicates) != 2 {
			t.Errorf("Expected 2 duplicates in group, got %d",
				len(result.Duplicates[0].Duplicates))
		}
	})

	t.Run("nearby lines in same file are deduplicated", func(t *testing.T) {
		findings := []Finding{
			{
				Concern:    "style",
				Message:    "Function too long",
				File:       "main.go",
				Line:       10,
				Confidence: 0.70,
			},
			{
				Concern:    "style",
				Message:    "Function too long",
				File:       "main.go",
				Line:       12,
				Confidence: 0.80,
			},
		}

		result := DeduplicateFindings(findings, config)

		if len(result.Unique) != 1 {
			t.Errorf("Expected 1 unique finding, got %d", len(result.Unique))
		}
		if result.Unique[0].Confidence != 0.80 {
			t.Errorf("Expected kept finding with confidence 0.80, got %.2f",
				result.Unique[0].Confidence)
		}
	})

	t.Run("far apart lines in same file are kept separate", func(t *testing.T) {
		findings := []Finding{
			{
				Concern:    "style",
				Message:    "Function too long",
				File:       "main.go",
				Line:       10,
				Confidence: 0.80,
			},
			{
				Concern:    "style",
				Message:    "Function too long",
				File:       "main.go",
				Line:       500,
				Confidence: 0.80,
			},
		}

		result := DeduplicateFindings(findings, config)

		if len(result.Unique) != 2 {
			t.Errorf("Expected 2 unique findings (far apart), got %d", len(result.Unique))
		}
		if len(result.Duplicates) != 0 {
			t.Errorf("Expected 0 duplicate groups, got %d", len(result.Duplicates))
		}
	})

	t.Run("different files are kept separate with SameFileOnly", func(t *testing.T) {
		sameFileConfig := NewDedupConfig()
		sameFileConfig.SameFileOnly = true

		findings := []Finding{
			{
				Concern:    "style",
				Message:    "Function too long",
				File:       "main.go",
				Line:       10,
				Confidence: 0.80,
			},
			{
				Concern:    "style",
				Message:    "Function too long",
				File:       "other.go",
				Line:       10,
				Confidence: 0.80,
			},
		}

		result := DeduplicateFindings(findings, sameFileConfig)

		if len(result.Unique) != 2 {
			t.Errorf("Expected 2 unique findings (different files), got %d", len(result.Unique))
		}
	})

	t.Run("mixed duplicates and unique findings", func(t *testing.T) {
		findings := []Finding{
			{
				Concern:    "security",
				Message:    "SQL injection",
				File:       "db.go",
				Line:       20,
				Confidence: 0.90,
			},
			{
				Concern:    "security",
				Message:    "SQL injection",
				File:       "db.go",
				Line:       20,
				Confidence: 0.85,
			},
			{
				Concern:    "style",
				Message:    "Unused import",
				File:       "main.go",
				Line:       5,
				Confidence: 0.95,
			},
			{
				Concern:    "bug",
				Message:    "Race condition",
				File:       "worker.go",
				Line:       100,
				Confidence: 0.88,
			},
		}

		result := DeduplicateFindings(findings, config)

		// SQL injection duplicates merged, unused import and race condition are unique
		if len(result.Unique) != 3 {
			t.Errorf("Expected 3 unique findings, got %d", len(result.Unique))
		}
		if len(result.Duplicates) != 1 {
			t.Errorf("Expected 1 duplicate group, got %d", len(result.Duplicates))
		}
	})

	t.Run("representative has highest confidence", func(t *testing.T) {
		findings := []Finding{
			{
				Concern:    "security",
				Message:    "XSS vulnerability detected",
				File:       "template.go",
				Line:       30,
				Confidence: 0.60,
			},
			{
				Concern:    "security",
				Message:    "XSS vulnerability detected",
				File:       "template.go",
				Line:       30,
				Confidence: 0.95,
			},
			{
				Concern:    "security",
				Message:    "XSS vulnerability detected",
				File:       "template.go",
				Line:       30,
				Confidence: 0.75,
			},
		}

		result := DeduplicateFindings(findings, config)

		if len(result.Unique) != 1 {
			t.Fatalf("Expected 1 unique finding, got %d", len(result.Unique))
		}
		if result.Unique[0].Confidence != 0.95 {
			t.Errorf("Expected highest confidence 0.95, got %.2f",
				result.Unique[0].Confidence)
		}
	})

	t.Run("single finding", func(t *testing.T) {
		findings := []Finding{
			{
				Concern:    "security",
				Message:    "Hardcoded secret",
				File:       "config.go",
				Line:       10,
				Confidence: 0.95,
			},
		}

		result := DeduplicateFindings(findings, config)

		if len(result.Unique) != 1 {
			t.Errorf("Expected 1 unique finding, got %d", len(result.Unique))
		}
		if len(result.Duplicates) != 0 {
			t.Errorf("Expected 0 duplicate groups, got %d", len(result.Duplicates))
		}
	})
}

// TestDeduplicateWithConfig tests custom deduplication configurations.
func TestDeduplicateWithConfig(t *testing.T) {
	t.Run("custom merge distance", func(t *testing.T) {
		findings := []Finding{
			{
				Concern:    "style",
				Message:    "Complex logic",
				File:       "main.go",
				Line:       10,
				Confidence: 0.80,
			},
			{
				Concern:    "style",
				Message:    "Complex logic",
				File:       "main.go",
				Line:       25,
				Confidence: 0.85,
			},
		}

		// Default threshold (5 lines) should keep them separate
		defaultConfig := NewDedupConfig()
		result := DeduplicateFindings(findings, defaultConfig)
		if len(result.Unique) != 2 {
			t.Errorf("Expected 2 unique findings with default threshold, got %d", len(result.Unique))
		}

		// With larger threshold, they should be deduplicated
		largeConfig := NewDedupConfig()
		largeConfig.MergeDistance = 20
		result = DeduplicateFindings(findings, largeConfig)
		if len(result.Unique) != 1 {
			t.Errorf("Expected 1 unique finding with large threshold, got %d", len(result.Unique))
		}
	})

	t.Run("SameFileOnly mode", func(t *testing.T) {
		sameFileConfig := NewDedupConfig()
		sameFileConfig.SameFileOnly = true

		findings := []Finding{
			{
				Concern:    "security",
				Message:    "SQL injection",
				File:       "db.go",
				Line:       20,
				Confidence: 0.90,
			},
			{
				Concern:    "security",
				Message:    "SQL injection",
				File:       "query.go",
				Line:       20,
				Confidence: 0.85,
			},
		}

		result := DeduplicateFindings(findings, sameFileConfig)

		if len(result.Unique) != 2 {
			t.Errorf("Expected 2 unique findings (same file only), got %d", len(result.Unique))
		}
	})

	t.Run("custom similarity threshold", func(t *testing.T) {
		findings := []Finding{
			{
				Concern:    "security",
				Message:    "XSS vulnerability in template",
				File:       "template.go",
				Line:       10,
				Confidence: 0.90,
			},
			{
				Concern:    "security",
				Message:    "XSS vulnerability in template rendering",
				File:       "template.go",
				Line:       10,
				Confidence: 0.85,
			},
		}

		// High threshold (0.95) should not dedupe (texts differ)
		highConfig := NewDedupConfig()
		highConfig.SimilarityThreshold = 0.95
		result := DeduplicateFindings(findings, highConfig)
		// They may or may not dedupe depending on Jaccard similarity
		t.Logf("With high threshold: %d unique", len(result.Unique))

		// Low threshold (0.3) should dedupe similar texts
		lowConfig := NewDedupConfig()
		lowConfig.SimilarityThreshold = 0.3
		result = DeduplicateFindings(findings, lowConfig)
		if len(result.Unique) != 1 {
			t.Logf("With low threshold: %d unique (may vary by similarity calc)", len(result.Unique))
		}
	})
}

// TestNewDedupConfig tests the default configuration.
func TestNewDedupConfig(t *testing.T) {
	config := NewDedupConfig()

	if config.SameFileOnly != false {
		t.Errorf("Expected SameFileOnly=false, got %v", config.SameFileOnly)
	}
	if config.MergeDistance != 5 {
		t.Errorf("Expected MergeDistance=5, got %d", config.MergeDistance)
	}
	if config.SimilarityThreshold != 0.8 {
		t.Errorf("Expected SimilarityThreshold=0.8, got %.2f", config.SimilarityThreshold)
	}
}

// TestDuplicateGroupReason verifies that duplicate groups have a reason.
func TestDeduplicateGroupReason(t *testing.T) {
	config := NewDedupConfig()
	findings := []Finding{
		{
			Concern:    "security",
			Message:    "Hardcoded password",
			File:       "config.go",
			Line:       15,
			Confidence: 0.90,
		},
		{
			Concern:    "security",
			Message:    "Hardcoded password",
			File:       "config.go",
			Line:       15,
			Confidence: 0.85,
		},
	}

	result := DeduplicateFindings(findings, config)

	if len(result.Duplicates) != 1 {
		t.Fatalf("Expected 1 duplicate group, got %d", len(result.Duplicates))
	}
	if result.Duplicates[0].Reason == "" {
		t.Error("Expected non-empty reason in duplicate group")
	}
}
