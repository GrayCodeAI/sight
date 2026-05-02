package sight

import "context"

// Provider is the LLM interface that consumers inject. This decouples sight
// from any specific LLM SDK. Hawk implements this using eyrie; tests use a mock.
type Provider interface {
	Chat(ctx context.Context, messages []Message, opts ChatOpts) (*Response, error)
}

// Message represents a single message in a conversation.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatOpts controls the LLM request.
type ChatOpts struct {
	Model       string  `json:"model,omitempty"`
	MaxTokens   int     `json:"max_tokens,omitempty"`
	Temperature float64 `json:"temperature,omitempty"`
	System      string  `json:"system,omitempty"`
}

// Response holds the LLM reply.
type Response struct {
	Content    string `json:"content"`
	TokensUsed int    `json:"tokens_used"`
}
