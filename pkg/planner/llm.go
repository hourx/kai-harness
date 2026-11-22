package planner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// LLM is the proposer that asks a model. It speaks the OpenAI chat-completions
// shape over plain net/http, so it points at whatever gateway the operator runs
// — a local router, a hosted endpoint — and drags in no client library. It is
// the only place in kai that reads a model's opinion, and it is optional: an
// unreachable endpoint is a note on the artifact, never a failed run.
type LLM struct {
	// Endpoint is the base URL up to and including the version segment, e.g.
	// "http://127.0.0.1:20128/v1". The "/chat/completions" path is appended.
	Endpoint  string
	Key       string
	Model     string
	MaxTokens int
	Client    *http.Client
}

// Name identifies the proposer in the artifact.
func (LLM) Name() string { return "llm" }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
}

type chatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		TotalTokens int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Propose asks the model for steps and returns them unvalidated. Validation is
// the kernel's job: this method's only promise is that it either returns steps
// the model wrote or an error saying why it could not.
func (l LLM) Propose(ctx context.Context, b Brief) ([]Step, Usage, error) {
	if strings.TrimSpace(l.Endpoint) == "" {
		return nil, Usage{}, errors.New("no planner endpoint is configured")
	}
	if strings.TrimSpace(l.Model) == "" {
		return nil, Usage{}, errors.New("no planner model is configured")
	}
	system, user := prompt(b)
	reqBody, err := json.Marshal(chatRequest{
		Model:       l.Model,
		Temperature: 0,
		MaxTokens:   l.MaxTokens,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	})
	if err != nil {
		return nil, Usage{}, err
	}

	url := strings.TrimRight(l.Endpoint, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, Usage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if l.Key != "" {
		req.Header.Set("Authorization", "Bearer "+l.Key)
	}
	client := l.Client
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, Usage{}, fmt.Errorf("calling the planner at %s: %w", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, Usage{}, err
	}
	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return nil, Usage{}, fmt.Errorf("the planner replied with %s: %s", resp.Status, firstLine(raw))
	}
	if cr.Error != nil {
		return nil, Usage{}, fmt.Errorf("the planner refused: %s", cr.Error.Message)
	}
	if resp.StatusCode != http.StatusOK && len(cr.Choices) == 0 {
		return nil, Usage{}, fmt.Errorf("the planner replied %s: %s", resp.Status, firstLine(raw))
	}
	if len(cr.Choices) == 0 {
		return nil, Usage{}, errors.New("the planner returned no choices")
	}
	content := cr.Choices[0].Message.Content
	body, err := extractJSON(content)
	if err != nil {
		return nil, Usage{}, fmt.Errorf("%w (finish_reason %q)", err, cr.Choices[0].FinishReason)
	}
	steps, err := decodeSteps(body)
	if err != nil {
		return nil, Usage{}, err
	}
	model := cr.Model
	if model == "" {
		model = l.Model
	}
	for i := range steps {
		steps[i].Target = strings.TrimSpace(steps[i].Target)
		steps[i].Action = ActionClass(strings.ToLower(strings.TrimSpace(string(steps[i].Action))))
		steps[i].Source = "llm:" + model
	}
	return steps, Usage{Model: model, Tokens: cr.Usage.TotalTokens}, nil
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

// decodeSteps accepts either a bare JSON array of steps or an object with a
// "steps" key, because models emit both and both are unambiguous.
func decodeSteps(body []byte) ([]Step, error) {
	var wrap struct {
		Steps []Step `json:"steps"`
	}
	if err := json.Unmarshal(body, &wrap); err == nil && wrap.Steps != nil {
		return wrap.Steps, nil
	}
	var steps []Step
	if err := json.Unmarshal(body, &steps); err != nil {
		return nil, fmt.Errorf("the model's JSON did not read as steps: %w", err)
	}
	return steps, nil
}

// extractJSON pulls the first balanced JSON value out of a model's reply, so a
// stray sentence or a ```json fence around it does not fail the parse.
func extractJSON(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
		if i := strings.LastIndex(s, "```"); i >= 0 {
			s = s[:i]
		}
		s = strings.TrimSpace(s)
	}
	start := strings.IndexAny(s, "{[")
	if start < 0 {
		return nil, errors.New("the model's reply carried no JSON")
	}
	open := s[start]
	closed := byte('}')
	if open == '[' {
		closed = ']'
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case open:
			depth++
		case closed:
			depth--
			if depth == 0 {
				return []byte(s[start : i+1]), nil
			}
		}
	}
	return nil, errors.New("the model's reply had no balanced JSON")
}

// prompt builds the two messages. The system message fixes the contract the way
// a schema would, and it says out loud what the validator enforces anyway: the
// model may only propose targets the scope already names, and it may never
// choose a destructive action.
func prompt(b Brief) (system, user string) {
	system = strings.Join([]string{
		"You plan security tests for one bug-bounty program.",
		"Reply with JSON only, no prose, in exactly this shape:",
		`{"steps":[{"target":"<host or URL>","class":"<finding class>","action":"read-only|state-changing","expected_oracle":"<what a positive result would look like>","rationale":"<one sentence>","pattern":"<optional pattern key>"}]}`,
		"Rules, in order of importance:",
		"1. A target is either a host from the brief's `hosts` list (e.g. \"api.example.com/orders\"), or a path on that surface (e.g. \"GET /orders\"). Any other host is discarded, so it is wasted. Never invent a host.",
		"2. Prefer read-only. Use state-changing only when the test truly requires a write, and say so in the rationale.",
		"3. Never propose a destructive action. It is refused.",
		"4. expected_oracle must be an observation a human could check — a status code, a field that should not be visible, a state that should not change.",
		"5. At most the number of steps asked for; fewer is fine. Rank by expected value.",
	}, "\n")
	jb, _ := json.MarshalIndent(b, "", "  ")
	user = "Here is the program brief as JSON. Propose the steps.\n\n" + string(jb)
	return system, user
}
