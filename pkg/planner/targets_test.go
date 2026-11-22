package planner

import (
	"strings"
	"testing"

	"github.com/hourx/kai-harness/pkg/scope"
)

// The queue the kernel writes names a target as "GET /path" — a path on the
// program's surface, with the host implied. Validate must accept that shape or
// the deterministic path produces nothing on a real workspace.
func TestValidateAcceptsPathOnlyTargets(t *testing.T) {
	g := testGate(t, []string{"*.shop.example"}, nil)
	steps := []Step{
		{Target: "GET /oauth/authorize", Class: "IDOR/BOLA", Action: ReadOnly, Expected: "B sees A's token"},
		{Target: "/orders", Class: "graphql", Action: ReadOnly, Expected: "introspection enabled"},
		{Target: "evil.example/z", Class: "graphql", Action: ReadOnly, Expected: "never"},
		{Target: "GET /admin", Class: "access-control", Action: StateChanging, Expected: "x"},
	}
	kept, dropped := Validate(steps, g, 12)
	if len(kept) != 3 {
		t.Fatalf("want 3 kept, got %d (%+v)", len(kept), kept)
	}
	for _, k := range kept[:2] {
		if !strings.Contains(k.Rationale, "path-only") {
			t.Errorf("path-only step not marked: %+v", k)
		}
	}
	if !strings.Contains(kept[2].Rationale, "state-changing") {
		t.Errorf("state-changing step not marked: %+v", kept[2])
	}
	if len(dropped) != 1 || !strings.Contains(dropped[0].Reason, "out of scope") {
		t.Fatalf("foreign host not dropped as out of scope: %+v", dropped)
	}
}

func TestValidateRefusesPathOnlyWhenTheScopeNamesNoHost(t *testing.T) {
	// A rule that is not a host cannot be attached to a path, so a path-only
	// step has nowhere to go and is refused rather than guessed at.
	g := scope.Gate{In: []string{"not a host"}}
	kept, dropped := Validate([]Step{{Target: "GET /x", Action: ReadOnly}}, g, 12)
	if len(kept) != 0 || len(dropped) != 1 {
		t.Fatalf("kept=%+v dropped=%+v", kept, dropped)
	}
	if !strings.Contains(dropped[0].Reason, "no host") {
		t.Errorf("reason = %q", dropped[0].Reason)
	}
}

func TestMethodPath(t *testing.T) {
	cases := []struct {
		in, method, path string
		ok               bool
	}{
		{"GET /orders/{id}", "GET", "/orders/{id}", true},
		{"post /orders", "POST", "/orders", true},
		{"/orders", "", "/orders", true},
		{"api.shop.example/orders", "", "", false},
		{"https://api.shop.example/orders", "", "", false},
		{"aliased.example", "", "", false},
		{"GET", "", "", false},
	}
	for _, c := range cases {
		m, p, ok := methodPath(c.in)
		if ok != c.ok || m != c.method || p != c.path {
			t.Errorf("methodPath(%q) = %q,%q,%v; want %q,%q,%v", c.in, m, p, ok, c.method, c.path, c.ok)
		}
	}
}
