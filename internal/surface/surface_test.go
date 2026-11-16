package surface

import (
	"strings"
	"testing"
	"time"

	"github.com/hourx/bountykit/internal/recon"
)

func TestModuleAndClass(t *testing.T) {
	cases := []struct {
		path   string
		module string
		class  string
	}{
		{"/api/v2/users/42", "users", "account"},
		{"/rest/v1/invoices/9", "invoices", "billing"},
		{"/admin/settings", "admin", "admin"},
		{"/oauth/token", "oauth", "auth"},
		{"/graphql", "graphql", "graphql"},
		{"/", "/", "generic"},
		{"/p/123", "p", "generic"},
	}
	for _, tc := range cases {
		if got := Module(tc.path); got != tc.module {
			t.Errorf("Module(%q) = %q, want %q", tc.path, got, tc.module)
		}
		if got := Class(tc.path); got != tc.class {
			t.Errorf("Class(%q) = %q, want %q", tc.path, got, tc.class)
		}
	}
}

func TestIsIDParam(t *testing.T) {
	yes := []string{"id", "ID", "user_id", "tenant-id", "order", "file"}
	no := []string{"", "page", "q", "sort", "callback"}
	for _, p := range yes {
		if !IsIDParam(p) {
			t.Errorf("IsIDParam(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if IsIDParam(p) {
			t.Errorf("IsIDParam(%q) = true, want false", p)
		}
	}
}

func TestObjectRef(t *testing.T) {
	cases := []struct {
		path string
		kind string
		ok   bool
	}{
		{"/api/users/42", "numeric", true},
		{"/api/orders/3f2504e0-4f89-11d3-9a0c-0305e82c3301", "uuid", true},
		{"/files/deadbeefdeadbeefdeadbeef", "hex", true},
		{"/api/users/me", "", false},
		{"/api/users/:user_id", "param", true},
		{"/api/users/{id}", "template", true},
		{"/api/users/${e}", "template", true},
		{"/412", "", false},
		{"/v2/reports", "", false},
	}
	for _, tc := range cases {
		ref, ok := ObjectRef(tc.path)
		if ok != tc.ok {
			t.Errorf("ObjectRef(%q) ok = %v, want %v", tc.path, ok, tc.ok)
			continue
		}
		if ok && ref.Kind != tc.kind {
			t.Errorf("ObjectRef(%q) kind = %q, want %q", tc.path, ref.Kind, tc.kind)
		}
	}
}

func TestBuildStats(t *testing.T) {
	endpoints := map[string][]string{
		"/api/v1/users/42": {"expand"},
		"/api/v1/orders":   {"order_id", "page"},
		"/api/v1/login":    nil,
		"/api/v1/graphql":  nil,
		"*":                {"lost"},
	}
	m := Build("p", endpoints, time.Now())
	if m.Stats.Endpoints != 4 {
		t.Errorf("Endpoints = %d, want 4 (the synthetic * key is not an endpoint)", m.Stats.Endpoints)
	}
	if m.Stats.Refs != 1 {
		t.Errorf("Refs = %d, want 1", m.Stats.Refs)
	}
	if len(m.IDParams) != 1 {
		t.Errorf("IDParams = %v, want only order_id (path refs are tracked separately)", m.IDParams)
	}
	if len(m.GraphQL) != 1 {
		t.Errorf("GraphQL = %v", m.GraphQL)
	}
	if len(m.APIVersions) != 1 || m.APIVersions[0] != "/api/v1" {
		t.Errorf("APIVersions = %v", m.APIVersions)
	}
	if !strings.Contains(m.Markdown(), "Surface map") {
		t.Error("markdown missing title")
	}
}

func TestBuildPlanRanking(t *testing.T) {
	now := time.Now()
	endpoints := map[string][]string{
		"/api/v1/users/42":    {"expand"},
		"/api/v1/billing/pay": {"amount"},
		"/api/v1/about":       nil,
	}
	m := Build("p", endpoints, now)
	d := &recon.Diff{NewEndpoints: []string{"/api/v1/about"}}
	hosts := map[string]*recon.HostRecord{
		"admin.example.com": {Host: "admin.example.com", Status: 403},
	}
	plan := BuildPlan("p", m, endpoints, d, hosts, now)
	if len(plan.Items) == 0 {
		t.Fatal("plan is empty")
	}
	top := plan.Items[0]
	if top.Class != "IDOR/BOLA" {
		t.Errorf("top item class = %q, want IDOR/BOLA (object ref + id param)", top.Class)
	}
	if top.Score < 110 {
		t.Errorf("top score = %d, want >= 110 (ref 50 + IDOR 50 + id param 15)", top.Score)
	}

	var newEndpointRanked, adminRanked bool
	for _, it := range plan.Items {
		if it.Target == "GET /api/v1/about" {
			newEndpointRanked = true
			if it.Score < 100 {
				t.Errorf("new endpoint score = %d, want >= 100", it.Score)
			}
		}
		if it.Target == "admin.example.com" && it.Class == "access-control" {
			adminRanked = true
		}
	}
	if !newEndpointRanked {
		t.Error("a brand-new endpoint must appear in the queue")
	}
	if !adminRanked {
		t.Error("a 403 admin host must be queued as access-control")
	}

	for i := 1; i < len(plan.Items); i++ {
		if plan.Items[i-1].Score < plan.Items[i].Score {
			t.Fatalf("items are not sorted by score: %d before %d", plan.Items[i-1].Score, plan.Items[i].Score)
		}
	}
	if !strings.Contains(plan.Markdown(), "Ranking is a hint") {
		t.Error("markdown should carry the ranking caveat")
	}
}

func TestHostWordMatchesIgnoresBaseDomain(t *testing.T) {
	cases := []struct {
		host string
		want []string
	}{
		{"admin.acme.test", []string{"admin"}},
		{"acme.test", nil},
		{"api.acme.test", []string{"api"}},
		{"foo.admin.acme.test", []string{"admin"}},
		{"dev-api.acme.test", []string{"dev", "api"}},
		{"www.acme.co.uk", nil},
	}
	for _, tc := range cases {
		got := hostWordMatches(tc.host)
		if len(got) != len(tc.want) {
			t.Errorf("hostWordMatches(%q) = %v, want %v", tc.host, got, tc.want)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("hostWordMatches(%q) = %v, want %v", tc.host, got, tc.want)
			}
		}
	}
}

func TestClassDoesNotMatchSubstrings(t *testing.T) {
	cases := map[string]string{
		"/api/profile":    "account", // contains "file" but must not be upload
		"/api/checkout":   "billing", // contains "check" but is a payment flow
		"/api/user-guide": "account", // token match, not the "file" substring
		"/api/files":      "upload",
		"/api/invoices":   "billing",
	}
	for path, want := range cases {
		if got := Class(path); got != want {
			t.Errorf("Class(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestAddNonWebRespectsConstraints(t *testing.T) {
	p := &Plan{Program: "p"}
	AddNonWeb(p, []NonWebAsset{
		{Identifier: "0xdeadbeef", Type: "CONTRACT"},
		{Identifier: "github.com/org/repo", Type: "SOURCE_CODE", Unverified: true},
		{Identifier: "api.example.com/v1/users", Type: "API", Detail: "path-restricted"},
	}, []string{"do not send test traffic to mainnet — use local forks"})

	if len(p.Items) != 3 {
		t.Fatalf("items = %v", p.Items)
	}
	byTarget := map[string]Hypothesis{}
	for _, h := range p.Items {
		byTarget[h.Target] = h
	}
	contract := byTarget["0xdeadbeef"]
	if contract.Class != "smart-contract" || contract.Score != 75 {
		t.Errorf("contract = %+v", contract)
	}
	if !strings.Contains(contract.Probe, "local fork") {
		t.Errorf("mainnet constraint not propagated: %s", contract.Probe)
	}
	repo := byTarget["github.com/org/repo"]
	if repo.Score != 40 || !strings.Contains(strings.Join(repo.Why, " "), "verify") {
		t.Errorf("unverified repo should be discounted and flagged: %+v", repo)
	}
	if byTarget["api.example.com/v1/users"].Class != "api-surface" {
		t.Errorf("api class = %q", byTarget["api.example.com/v1/users"].Class)
	}
	for i := 1; i < len(p.Items); i++ {
		if p.Items[i-1].Score < p.Items[i].Score {
			t.Fatal("AddNonWeb must keep the queue sorted")
		}
	}
}

func TestBuildWithNonWebRecordsAssets(t *testing.T) {
	assets := []NonWebAsset{{Identifier: "com.example.app", Type: "GOOGLE_PLAY_APP_ID"}}
	m := BuildWithNonWeb("p", map[string][]string{}, assets, time.Now())
	if len(m.NonWeb) != 1 || m.Stats.Endpoints != 0 {
		t.Errorf("map = %+v", m)
	}
	if !strings.Contains(m.Markdown(), "Non-web assets") {
		t.Error("map markdown should list non-web assets")
	}
}

func TestBuildPlanEmpty(t *testing.T) {
	plan := BuildPlan("p", Build("p", map[string][]string{}, time.Now()), map[string][]string{}, nil, nil, time.Now())
	if len(plan.Items) != 0 {
		t.Errorf("expected an empty plan, got %+v", plan.Items)
	}
	if !strings.Contains(plan.Markdown(), "No hypothesis cleared the evidence bar") {
		t.Error("empty plan should say so plainly")
	}
}
