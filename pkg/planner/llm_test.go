package planner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeRouter answers like an OpenAI-compatible gateway, so the client can be
// tested without a model behind it. wantKey is asserted only when non-empty.
func fakeRouter(t *testing.T, content string, tokens int, wantKey string, capture *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if wantKey != "" {
			if got := r.Header.Get("Authorization"); got != "Bearer "+wantKey {
				t.Errorf("auth header = %q", got)
			}
		}
		if capture != nil {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			*capture = body
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": "test-model",
			"choices": []map[string]any{
				{"message": map[string]any{"content": content}, "finish_reason": "stop"},
			},
			"usage": map[string]any{"total_tokens": tokens},
		})
	}))
}

func TestLLMProposeReadsABareArray(t *testing.T) {
	var body map[string]any
	srv := fakeRouter(t, `[{"target":"api.shop.example/orders","class":"IDOR/BOLA","action":"Read-Only","expected_oracle":"B sees A's data"}]`, 88, "test-key", &body)
	defer srv.Close()

	l := LLM{Endpoint: srv.URL + "/v1", Key: "test-key", Model: "test-model"}
	steps, usage, err := l.Propose(context.Background(), Brief{Program: "shop"})
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || steps[0].Target != "api.shop.example/orders" {
		t.Fatalf("steps = %+v", steps)
	}
	// The action string is lowercased so an odd case still validates.
	if steps[0].Action != ReadOnly {
		t.Errorf("action = %q, want read-only", steps[0].Action)
	}
	if steps[0].Source != "llm:test-model" {
		t.Errorf("source = %q", steps[0].Source)
	}
	if usage.Tokens != 88 || usage.Model != "test-model" {
		t.Errorf("usage = %+v", usage)
	}
	// The request must be deterministic and carry the system contract.
	if body["temperature"].(float64) != 0 {
		t.Errorf("temperature = %v, want 0", body["temperature"])
	}
	msgs := body["messages"].([]any)
	sys := msgs[0].(map[string]any)["content"].(string)
	if !strings.Contains(sys, "JSON only") || !strings.Contains(sys, "hosts") {
		t.Errorf("system prompt is missing the contract: %q", sys)
	}
	if body["model"] != "test-model" {
		t.Errorf("model not sent: %v", body["model"])
	}
}

func TestLLMProposeReadsAWrappedFencedReply(t *testing.T) {
	reply := "Sure, here you go:\n```json\n{\"steps\":[{\"target\":\"a.example\",\"action\":\"read-only\"}]}\n```"
	srv := fakeRouter(t, reply, 12, "", nil)
	defer srv.Close()
	l := LLM{Endpoint: srv.URL + "/v1", Model: "m"}
	steps, _, err := l.Propose(context.Background(), Brief{})
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || steps[0].Target != "a.example" {
		t.Fatalf("steps = %+v", steps)
	}
}

func TestLLMProposeSurfacesAnErrorObject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "credit balance is too low"}})
	}))
	defer srv.Close()
	l := LLM{Endpoint: srv.URL, Model: "m"}
	_, _, err := l.Propose(context.Background(), Brief{})
	if err == nil || !strings.Contains(err.Error(), "credit balance") {
		t.Fatalf("err = %v", err)
	}
}

func TestLLMProposeRejectsProse(t *testing.T) {
	srv := fakeRouter(t, "I would start by looking at the login page.", 5, "", nil)
	defer srv.Close()
	l := LLM{Endpoint: srv.URL, Model: "m"}
	if _, _, err := l.Propose(context.Background(), Brief{}); err == nil {
		t.Fatal("prose must not parse as steps")
	}
}

func TestLLMNeedsEndpointAndModel(t *testing.T) {
	if _, _, err := (LLM{Model: "m"}).Propose(context.Background(), Brief{}); err == nil {
		t.Error("missing endpoint must fail")
	}
	if _, _, err := (LLM{Endpoint: "http://x/v1"}).Propose(context.Background(), Brief{}); err == nil {
		t.Error("missing model must fail")
	}
}

func TestExtractJSON(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{`{"steps":[]}`, `{"steps":[]}`, true},
		{"```json\n[1,2]\n```", `[1,2]`, true},
		{"prefix {\"a\":{\"b\":1}} suffix", `{"a":{"b":1}}`, true},
		{`note "}" then {"a":1}`, `{"a":1}`, true},
		{"no json here", "", false},
		{`{"unbalanced":`, "", false},
	}
	for _, c := range cases {
		got, err := extractJSON(c.in)
		if c.ok && (err != nil || string(got) != c.want) {
			t.Errorf("extractJSON(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("extractJSON(%q) = %q, want error", c.in, got)
		}
	}
}
