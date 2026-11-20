package archetype

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hourx/kai-harness/pkg/surface"
)

func TestNormalizeAliases(t *testing.T) {
	cases := map[string]string{
		"GraphQL":         GraphQLAPI,
		"graphql_gateway": GraphQLAPI,
		"REST API":        API,
		"rest-api":        API,
		" Android ":       MobileAPI,
		"Web":             WebApp,
		"smart_contract":  Chain,
		"zk-rollup":       "zk-rollup",
		"":                "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKnownIsClosedSet(t *testing.T) {
	for _, n := range Names() {
		if !Known(n) {
			t.Errorf("%s should be known", n)
		}
	}
	if Known("zk-rollup") || Known("") {
		t.Error("Known accepted a name outside the closed set")
	}
	if len(Names()) != 7 {
		t.Errorf("Names() = %v, want 7 entries", Names())
	}
}

func TestDeclaredWins(t *testing.T) {
	m := &surface.Map{Modules: map[string][]string{"api": {"/api/v1/orders"}}}
	v := Classify("chain", m, nil)
	if v.Name != Chain || v.Source != "declared" || v.Confidence != "high" {
		t.Fatalf("declared verdict = %+v", v)
	}
	if len(v.Why) == 0 || !strings.Contains(v.Why[0], "declares") {
		t.Errorf("declared verdict must cite the contract: %v", v.Why)
	}
}

func TestDeclaredUnknownNameIsLoud(t *testing.T) {
	v := Classify("zk-rollup", nil, nil)
	if v.Name != "zk-rollup" || v.Confidence != "low" {
		t.Fatalf("verdict = %+v", v)
	}
	joined := strings.Join(v.Why, " ")
	if !strings.Contains(joined, "not one of the known archetypes") {
		t.Errorf("an unusual declaration must be flagged: %v", v.Why)
	}
}

func TestInferNilMapIsUnknown(t *testing.T) {
	v := Classify("", nil, nil)
	if v.Name != Unknown || v.Source != "inferred" {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestInferChain(t *testing.T) {
	nonWeb := []surface.NonWebAsset{
		{Identifier: "0xabc", Type: "contract"},
		{Identifier: "0xdef", Type: "program"},
	}
	v := Classify("", &surface.Map{Modules: map[string][]string{}}, nonWeb)
	if v.Name != Chain || v.Confidence != "high" {
		t.Fatalf("verdict = %+v", v)
	}
	if len(v.Signals) == 0 || !strings.Contains(v.Signals[0], "chain_assets=2") {
		t.Errorf("signals = %v", v.Signals)
	}
}

func TestInferGraphQL(t *testing.T) {
	m := &surface.Map{
		GraphQL: []string{"/graphql", "/api/v1/graphql", "/gql", "/query"},
		Modules: map[string][]string{
			"api": {"/api/v1/graphql", "/api/v1/me", "/api/v1/orders", "/api/v1/users", "/api/v1/cart", "/api/v1/search"},
		},
	}
	v := Classify("", m, nil)
	if v.Name != GraphQLAPI {
		t.Fatalf("verdict = %+v", v)
	}
	if v.Confidence != "high" {
		t.Errorf("confidence = %s, want high (why=%v)", v.Confidence, v.Why)
	}
}

func TestInferAPI(t *testing.T) {
	m := &surface.Map{
		APIVersions: []string{"v2"},
		Modules: map[string][]string{"api": {
			"/api/v2/users", "/api/v2/orders", "/api/v2/items", "/api/internal/health",
		}},
	}
	v := Classify("", m, nil)
	if v.Name != API || v.Confidence != "high" {
		t.Fatalf("verdict = %+v", v)
	}
	if !strings.Contains(strings.Join(v.Signals, ","), "api_version=v2") {
		t.Errorf("signals = %v", v.Signals)
	}
}

func TestInferWebApp(t *testing.T) {
	m := &surface.Map{Modules: map[string][]string{
		"account":   {"/account/profile", "/account/settings"},
		"auth":      {"/login", "/logout"},
		"dashboard": {"/dashboard/overview"},
	}}
	v := Classify("", m, nil)
	if v.Name != WebApp || v.Confidence != "high" {
		t.Fatalf("verdict = %+v", v)
	}
	joined := strings.Join(v.Why, " ")
	if !strings.Contains(joined, "authentication endpoints") {
		t.Errorf("auth endpoints should be cited: %v", v.Why)
	}
}

func TestInferMobileAPI(t *testing.T) {
	m := &surface.Map{Modules: map[string][]string{
		"app": {"/app/v1/sync", "/app/v1/device", "/app/v1/push/events", "/mobile/config"},
	}}
	v := Classify("", m, nil)
	if v.Name != MobileAPI || v.Confidence != "high" {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestTooLittleEvidenceStaysUnknown(t *testing.T) {
	m := &surface.Map{Modules: map[string][]string{"weird": {"/x/y"}}}
	v := Classify("", m, nil)
	if v.Name != Unknown {
		t.Fatalf("one unexplained path must not name an archetype: %+v", v)
	}
	if !strings.Contains(strings.Join(v.Why, " "), "too little evidence") {
		t.Errorf("why = %v", v.Why)
	}
}

func TestInferIsDeterministic(t *testing.T) {
	m := &surface.Map{
		Modules: map[string][]string{"api": {"/api/v1/a", "/api/v1/b"}, "account": {"/account/x"}},
		GraphQL: []string{"/graphql"},
	}
	a, _ := json.Marshal(Classify("", m, nil))
	b, _ := json.Marshal(Classify("", m, nil))
	if string(a) != string(b) {
		t.Errorf("same map, different verdict:\n%s\n%s", a, b)
	}
}

func TestClassifyUsesMapNonWebWhenNotPassed(t *testing.T) {
	m := &surface.Map{
		Modules: map[string][]string{},
		NonWeb:  []surface.NonWebAsset{{Identifier: "0xabc", Type: "contract"}},
	}
	if v := Classify("", m, nil); v.Name != Chain {
		t.Fatalf("map.NonWeb must be honoured: %+v", v)
	}
}

func TestMarkdownNamesTheArchetype(t *testing.T) {
	md := Markdown(Classify("api", nil, nil))
	for _, want := range []string{"# Archetype: api", "confidence: high", "source: declared"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

// A declared archetype is only respected if every spelling of a name lands in
// the same closed set: a contract that says "GraphQLAPI" must not be treated as
// an unknown name and quietly downgraded to generic sweeps.
func TestNormalizeHandsConcatenatedSpellingsToTheClosedSet(t *testing.T) {
	cases := map[string]string{
		"GraphQLAPI":      GraphQLAPI,
		"graphql_api":     GraphQLAPI,
		"gql":             GraphQLAPI,
		"graphql-gateway": GraphQLAPI,
		"WebApp":          WebApp,
		"webapp":          WebApp,
		"frontend":        WebApp,
		"MobileAPI":       MobileAPI,
		"android":         MobileAPI,
		"Chain":           Chain,
		"web3":            Chain,
		"smart_contract":  Chain,
		"REST":            API,
		"rest_api":        API,
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
		if !Known(in) {
			t.Errorf("Known(%q) = false", in)
		}
	}

	v := Classify("GraphQLAPI", nil, nil)
	if v.Name != GraphQLAPI || v.Confidence != "high" || v.Source != "declared" {
		t.Errorf("declared camel-case name mishandled: %+v", v)
	}
	if len(v.Why) != 1 {
		t.Errorf("a known declaration must not be doubted: %+v", v)
	}
	// An unknown declaration is still honoured, but flagged.
	v = Classify("something-new", nil, nil)
	if v.Name != "something-new" || v.Confidence != "low" {
		t.Errorf("unknown declaration should be kept and doubted: %+v", v)
	}
}
