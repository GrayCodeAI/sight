package sight

import (
	"sync"
	"testing"
)

func TestIncrementalState_Basic(t *testing.T) {
	state := NewIncrementalState("")
	if got := state.LastReviewedSHA(); got != "" {
		t.Errorf("expected empty SHA, got %q", got)
	}

	state.SetLastReviewedSHA("abc123")
	if got := state.LastReviewedSHA(); got != "abc123" {
		t.Errorf("expected 'abc123', got %q", got)
	}
}

func TestIncrementalState_Seeded(t *testing.T) {
	state := NewIncrementalState("initial-sha")
	if got := state.LastReviewedSHA(); got != "initial-sha" {
		t.Errorf("expected 'initial-sha', got %q", got)
	}
}

func TestIncrementalState_Update(t *testing.T) {
	state := NewIncrementalState("sha1")
	state.SetLastReviewedSHA("sha2")
	if got := state.LastReviewedSHA(); got != "sha2" {
		t.Errorf("expected 'sha2', got %q", got)
	}
	state.SetLastReviewedSHA("sha3")
	if got := state.LastReviewedSHA(); got != "sha3" {
		t.Errorf("expected 'sha3', got %q", got)
	}
}

func TestIncrementalState_Concurrent(t *testing.T) {
	state := NewIncrementalState("")
	var wg sync.WaitGroup

	// Write from multiple goroutines to test thread safety
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(sha string) {
			defer wg.Done()
			state.SetLastReviewedSHA(sha)
			_ = state.LastReviewedSHA()
		}("sha-" + string(rune('a'+i%26)))
	}
	wg.Wait()

	// Should not panic or race; any value is fine
	got := state.LastReviewedSHA()
	if got == "" {
		t.Error("expected non-empty SHA after concurrent writes")
	}
}
