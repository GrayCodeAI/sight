package sight

import (
	"sort"
	"strings"
)

// DedupConfig controls how findings are deduplicated.
type DedupConfig struct {
	SameFileOnly        bool    // Only merge findings within the same file
	MergeDistance       int     // Line distance threshold for merging nearby findings
	SimilarityThreshold float64 // Jaccard similarity threshold (0-1) for treating findings as near-duplicates
}

// DedupResult contains the outcome of a deduplication pass.
type DedupResult struct {
	Unique     []Finding        // Findings that survived deduplication
	Duplicates []DuplicateGroup // Groups of findings that were merged
}

// DuplicateGroup describes a set of findings collapsed into one representative.
type DuplicateGroup struct {
	Representative Finding   // The highest-confidence finding in the group
	Duplicates     []Finding // The remaining findings that were folded in
	Reason         string    // Human-readable explanation of why they were grouped
}

// NewDedupConfig returns a DedupConfig with sensible defaults.
func NewDedupConfig() DedupConfig {
	return DedupConfig{
		SameFileOnly:        false,
		MergeDistance:       5,
		SimilarityThreshold: 0.8,
	}
}

// DeduplicateFindings removes duplicate or near-duplicate findings.
// It groups findings that have similar concern+message text and are nearby
// in line distance, keeping the highest-confidence finding as the representative.
func DeduplicateFindings(findings []Finding, config DedupConfig) DedupResult {
	if len(findings) == 0 {
		return DedupResult{
			Unique:     []Finding{},
			Duplicates: []DuplicateGroup{},
		}
	}

	// Track which findings have already been assigned to a group.
	assigned := make(map[int]bool)
	var groups []DuplicateGroup

	for i := 0; i < len(findings); i++ {
		if assigned[i] {
			continue
		}

		group := []Finding{findings[i]}
		assigned[i] = true

		for j := i + 1; j < len(findings); j++ {
			if assigned[j] {
				continue
			}

			if areSimilar(findings[i], findings[j], config.SimilarityThreshold) &&
				areNearby(findings[i], findings[j], config.SameFileOnly, config.MergeDistance) {
				group = append(group, findings[j])
				assigned[j] = true
			}
		}

		if len(group) == 1 {
			// Sole member: no duplicates found, keep as unique.
			// Undo the assigned[i] = true set above so the second pass picks it up.
			assigned[i] = false
			continue
		}

		// Sort by confidence descending to pick the best representative.
		sort.Slice(group, func(a, b int) bool {
			return group[a].Confidence > group[b].Confidence
		})

		groups = append(groups, DuplicateGroup{
			Representative: group[0],
			Duplicates:     group[1:],
			Reason:         buildReason(group[0], group[1:], config),
		})
	}

	// Collect unique findings: unassigned ones plus the representative of each group.
	unique := make([]Finding, 0, len(findings))
	for i := range findings {
		if !assigned[i] {
			unique = append(unique, findings[i])
		}
	}
	for _, g := range groups {
		unique = append(unique, g.Representative)
	}

	if unique == nil {
		unique = []Finding{}
	}
	if groups == nil {
		groups = []DuplicateGroup{}
	}

	return DedupResult{
		Unique:     unique,
		Duplicates: groups,
	}
}

// areSimilar checks whether two findings have similar concern and message
// text using Jaccard similarity on their word sets.
func areSimilar(a, b Finding, threshold float64) bool {
	wordsA := extractWords(a.Concern + " " + a.Message)
	wordsB := extractWords(b.Concern + " " + b.Message)

	if len(wordsA) == 0 && len(wordsB) == 0 {
		return true
	}
	if len(wordsA) == 0 || len(wordsB) == 0 {
		return false
	}

	setA := make(map[string]struct{}, len(wordsA))
	for _, w := range wordsA {
		setA[w] = struct{}{}
	}
	setB := make(map[string]struct{}, len(wordsB))
	for _, w := range wordsB {
		setB[w] = struct{}{}
	}

	intersection := 0
	for w := range setA {
		if _, ok := setB[w]; ok {
			intersection++
		}
	}

	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return true
	}

	jaccard := float64(intersection) / float64(union)
	return jaccard >= threshold
}

// areNearby checks whether two findings are close enough in proximity
// to be considered candidates for deduplication.
func areNearby(a, b Finding, sameFileOnly bool, distance int) bool {
	if sameFileOnly && a.File != b.File {
		return false
	}

	// Different files when sameFileOnly is false: allow cross-file dedup
	// based purely on text similarity (proximity is meaningless across files).
	if a.File != b.File {
		return true
	}

	lineDiff := a.Line - b.Line
	if lineDiff < 0 {
		lineDiff = -lineDiff
	}
	return lineDiff <= distance
}

// extractWords tokenises a string into lowercased words.
func extractWords(s string) []string {
	s = strings.ToLower(s)
	fields := strings.Fields(s)
	words := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.Trim(f, ".,;:!?\"'()[]{}")
		if f != "" {
			words = append(words, f)
		}
	}
	return words
}

// buildReason produces a human-readable explanation for why a group was merged.
func buildReason(rep Finding, dupes []Finding, config DedupConfig) string {
	var parts []string

	if config.SameFileOnly {
		parts = append(parts, "same file")
	}

	if len(dupes) == 1 {
		parts = append(parts, "similar concern/message text")
	} else {
		parts = append(parts, "similar concern/message text")
	}

	if rep.File != "" && len(dupes) > 0 && dupes[0].File == rep.File {
		parts = append(parts, "within line distance threshold")
	}

	return strings.Join(parts, ", ")
}
