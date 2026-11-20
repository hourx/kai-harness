package serve

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hourx/kai-harness/pkg/board"
	"github.com/hourx/kai-harness/pkg/recon"
)

// fixture builds a workspace on disk with one program, using the same file
// layout the CLI writes. The service is then asked about that state, so the test
// fails if the API ever reports something the files do not say.
func fixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("KAI_HOME", home)
	dir := filepath.Join(home, "demo")
	for _, sub := range []string{"state", "evidence", "findings"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("meta.json", `{"name":"demo","platform":"hackerone","program_url":"https://hackerone.com/demo",`+
		`"scope_verdict":"money","created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-20T10:00:00Z"}`)
	write("scope.txt", "*.demo.example\napi.demo.example\n")
	write("out-of-scope.txt", "admin.demo.example\n")
	write("urls.txt", "https://a.demo.example/1\nhttps://a.demo.example/2\nhttps://b.demo.example/3\n")
	write("endpoints.txt", "/v1/orders\n/v1/users\n/v1/invoices\n")
	write("next.json", `{"program":"demo","generated":"2026-11-20T10:00:00Z","items":[`+
		`{"target":"GET /v1/orders","class":"IDOR/BOLA","score":90,"why":["numeric id"],"probe":"two accounts"},`+
		`{"target":"GET /v1/users","class":"IDOR/BOLA","score":70,"why":["id param"],"probe":"swap id"}]}`)
	write(filepath.Join("state", "outcomes.jsonl"),
		`{"ts":"2026-11-19T10:00:00Z","target":"GET /v1/a","status":"negation","note":"401 no data"}`+"\n"+
			`{"ts":"2026-11-19T11:00:00Z","target":"GET /v1/b","status":"informational"}`+"\n")
	write(filepath.Join("evidence", "index.json"),
		`[{"id":"ev-1","ts":"2026-11-19T10:00:00Z","kind":"http","target":"GET /v1/a","status":401}]`)
	write(filepath.Join("findings", "ledger.json"),
		`{"program":"demo","findings":[{"id":"F1","target":"GET /v1/orders","status":"candidate"},`+
			`{"id":"F2","target":"GET /v1/users","status":"paid"}]}`)
	return home
}

func do(t *testing.T, h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body.String())
	}
	return out
}

func TestValidateAddrRefusesPublicWithoutToken(t *testing.T) {
	cases := []struct {
		addr  string
		token string
		ok    bool
	}{
		{"127.0.0.1:8788", "", true},
		{"localhost:8788", "", true},
		{"[::1]:8788", "", true},
		{"0.0.0.0:8788", "", false},
		{":8788", "", false},
		{"192.168.1.10:8788", "", false},
		{"0.0.0.0:8788", "secret", true},
		{"192.168.1.10:8788", "secret", true},
		{"nonsense", "", false},
	}
	for _, c := range cases {
		err := ValidateAddr(c.addr, c.token)
		if c.ok && err != nil {
			t.Errorf("ValidateAddr(%q, %q) = %v, want nil", c.addr, c.token, err)
		}
		if !c.ok && err == nil {
			t.Errorf("ValidateAddr(%q, %q) = nil, want an error", c.addr, c.token)
		}
	}
}

func TestHealthNeedsNoToken(t *testing.T) {
	fixture(t)
	s := New("", "secret")
	rec := do(t, s.Handler(), "GET", "/healthz", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := decode(t, rec)["ok"]; got != true {
		t.Fatalf("ok = %v", got)
	}
}

func TestTokenGate(t *testing.T) {
	fixture(t)
	s := New("", "secret")
	h := s.Handler()

	for _, c := range []struct {
		name  string
		token string
		want  int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"wrong token", "wrong", http.StatusUnauthorized},
		{"right token", "secret", http.StatusOK},
	} {
		rec := do(t, h, "GET", APIPrefix+"/programs", c.token)
		if rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d", c.name, rec.Code, c.want)
		}
	}
	if rec := do(t, h, "GET", APIPrefix+"/programs", ""); rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("401 without a WWW-Authenticate challenge")
	}
}

// A loopback server with no token configured is the development case: everything
// is readable, which is why it is loopback-only.
func TestNoTokenOnLoopbackIsOpen(t *testing.T) {
	fixture(t)
	s := New("", "")
	rec := do(t, s.Handler(), "GET", APIPrefix+"/board", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestProgramsListReflectsDisk(t *testing.T) {
	fixture(t)
	s := New("", "")
	rec := do(t, s.Handler(), "GET", APIPrefix+"/programs", "")
	body := decode(t, rec)
	programs, _ := body["programs"].([]any)
	if len(programs) != 1 {
		t.Fatalf("programs = %v", body["programs"])
	}
	first, _ := programs[0].(map[string]any)
	if first["name"] != "demo" || first["platform"] != "hackerone" || first["scope_verdict"] != "money" {
		t.Fatalf("meta = %v", first)
	}
	if first["updated_at"] != "2026-11-20T10:00:00Z" {
		t.Fatalf("updated_at = %v", first["updated_at"])
	}
	arts, _ := first["artifacts"].(map[string]any)
	if arts["urls.txt"] != float64(3) || arts["endpoints.txt"] != float64(3) {
		t.Fatalf("artifacts = %v", arts)
	}
	scope, _ := first["scope"].(map[string]any)
	if scope["in_rules"] != float64(2) || scope["out_rules"] != float64(1) {
		t.Fatalf("scope = %v", scope)
	}
	// The list stays light: no queue items.
	queue, _ := first["queue"].(map[string]any)
	if items, _ := queue["items"].([]any); len(items) != 0 {
		t.Fatalf("list carried queue items: %v", items)
	}
	if queue["total"] != float64(2) {
		t.Fatalf("queue total = %v", queue["total"])
	}
}

func TestDetailCarriesQueueFindingsOutcomes(t *testing.T) {
	fixture(t)
	s := New("", "")
	rec := do(t, s.Handler(), "GET", APIPrefix+"/programs/demo", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	body := decode(t, rec)

	queue, _ := body["queue"].(map[string]any)
	items, _ := queue["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("queue items = %v", items)
	}
	top, _ := items[0].(map[string]any)
	if top["target"] != "GET /v1/orders" || top["score"] != float64(90) {
		t.Fatalf("top item = %v", top)
	}

	findings, _ := body["findings"].(map[string]any)
	if findings["total"] != float64(2) {
		t.Fatalf("findings = %v", findings)
	}
	byStatus, _ := findings["by_status"].(map[string]any)
	if byStatus["candidate"] != float64(1) || byStatus["paid"] != float64(1) {
		t.Fatalf("findings by_status = %v", byStatus)
	}

	outcomes, _ := body["outcomes"].(map[string]any)
	if outcomes["total"] != float64(2) {
		t.Fatalf("outcomes = %v", outcomes)
	}
	recent, _ := outcomes["recent"].([]any)
	last, _ := recent[len(recent)-1].(map[string]any)
	if last["target"] != "GET /v1/b" {
		t.Fatalf("recent order = %v", recent)
	}

	if body["evidence"] != float64(1) {
		t.Fatalf("evidence = %v", body["evidence"])
	}

	plan, _ := body["plan"].(map[string]any)
	waves, _ := plan["waves"].([]any)
	if len(waves) == 0 {
		t.Fatalf("plan had no waves: %v", plan)
	}
}

func TestQueueLimitAndOrder(t *testing.T) {
	fixture(t)
	s := New("", "")
	rec := do(t, s.Handler(), "GET", APIPrefix+"/programs/demo/queue?limit=1", "")
	body := decode(t, rec)
	items, _ := body["items"].([]any)
	if len(items) != 1 || body["total"] != float64(2) || body["limit"] != float64(1) {
		t.Fatalf("limited queue = %v", body)
	}
	// A bad or huge limit falls back to the default rather than failing.
	for _, q := range []string{"?limit=abc", "?limit=-4", "?limit=99999"} {
		rec := do(t, s.Handler(), "GET", APIPrefix+"/programs/demo/queue"+q, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", q, rec.Code)
		}
	}
	big := decode(t, do(t, s.Handler(), "GET", APIPrefix+"/programs/demo/queue?limit=99999", ""))
	if big["limit"] != float64(maxQueueLimit) {
		t.Fatalf("limit clamp = %v", big["limit"])
	}
}

func TestScopeVerdictEndpoint(t *testing.T) {
	fixture(t)
	s := New("", "")
	h := s.Handler()
	cases := []struct {
		host    string
		verdict string
	}{
		{"api.demo.example", "IN"},
		{"x.demo.example", "IN"},
		{"admin.demo.example", "OUT"},
		{"demo.example", "OUT"}, // a wildcard rule never covers the apex
		{"evil.example", "OUT"}, // unknown hosts are out, not assumed in
	}
	for _, c := range cases {
		rec := do(t, h, "GET", APIPrefix+"/programs/demo/scope?host="+c.host, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", c.host, rec.Code)
		}
		body := decode(t, rec)
		if body["verdict"] != c.verdict {
			t.Errorf("%s: verdict = %v, want %s", c.host, body["verdict"], c.verdict)
		}
	}
	if rec := do(t, h, "GET", APIPrefix+"/programs/demo/scope", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing host: status = %d", rec.Code)
	}
}

func TestUnknownProgramAndRoute(t *testing.T) {
	fixture(t)
	s := New("", "")
	for _, path := range []string{
		APIPrefix + "/programs/nope",
		APIPrefix + "/programs/nope/queue",
		APIPrefix + "/programs/..",
		APIPrefix + "/nothing",
		"/random",
	} {
		rec := do(t, s.Handler(), "GET", path, "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "error") {
			t.Errorf("%s: body = %s", path, rec.Body.String())
		}
	}
	if rec := do(t, s.Handler(), "GET", APIPrefix+"/programs/demo/nope", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown sub-route: status = %d", rec.Code)
	}
}

func TestMutationsAreRefused(t *testing.T) {
	fixture(t)
	s := New("", "")
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		rec := do(t, s.Handler(), method, APIPrefix+"/programs", "")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: status = %d, want 405", method, rec.Code)
		}
		if rec.Header().Get("Allow") == "" {
			t.Fatalf("%s: no Allow header", method)
		}
	}
}

func TestDashboardIsServed(t *testing.T) {
	fixture(t)
	rec := do(t, New("", "").Handler(), "GET", "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %s", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"<title>kai", APIPrefix + "/board", "kai.token", "LIVE RUN", "data-live", "closest('button[data-live]"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard is missing %q", want)
		}
	}
}

// The dashboard reads the API, so every path it fetches must exist.
func TestDashboardPathsExist(t *testing.T) {
	fixture(t)
	h := New("", "").Handler()
	page := do(t, h, "GET", "/", "").Body.String()
	var paths []string
	for _, chunk := range strings.Split(page, "'") {
		if strings.HasPrefix(chunk, APIPrefix) {
			paths = append(paths, chunk)
		}
	}
	if len(paths) < 3 {
		t.Fatalf("found no API paths in the dashboard: %v", paths)
	}
	for _, p := range paths {
		// Strip the query and the HTML-escaped concatenations.
		p = strings.ReplaceAll(p, "&amp;", "&")
		p = strings.ReplaceAll(p, "'+", "")
		if i := strings.Index(p, "?"); i >= 0 {
			p = p[:i]
		}
		if !strings.HasPrefix(p, APIPrefix) || strings.ContainsAny(p, "+ ") {
			continue
		}
		if p == APIPrefix+"/programs/" {
			continue
		}
		rec := do(t, h, "GET", p, "")
		if rec.Code == http.StatusNotFound {
			t.Errorf("dashboard fetches a missing path: %s", p)
		}
	}
}

func TestBriefWithoutIntakeExplainsItself(t *testing.T) {
	fixture(t)
	rec := do(t, New("", "").Handler(), "GET", APIPrefix+"/programs/demo/brief", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "kai intake") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestEmptyHomeIsNotAnError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KAI_HOME", home)
	s := New("", "")
	rec := do(t, s.Handler(), "GET", APIPrefix+"/programs", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if body := decode(t, rec); body["home"] != home {
		t.Fatalf("home = %v", body["home"])
	}
	rec = do(t, s.Handler(), "GET", APIPrefix+"/board", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("board on an empty home: status = %d", rec.Code)
	}
}

func TestServeListensAndStops(t *testing.T) {
	fixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- New("", "").Serve(ctx, addr) }()

	client := &http.Client{Timeout: time.Second}
	var lastErr error
	up := false
	for i := 0; i < 50; i++ {
		resp, err := client.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			up = true
			break
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	if !up {
		t.Fatalf("server never came up: %v", lastErr)
	}

	resp, err := client.Get("http://" + addr + APIPrefix + "/programs")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("programs over the wire: %d", resp.StatusCode)
	}
	resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop on cancel")
	}
}

func TestServeRefusesPublicBindAtStartup(t *testing.T) {
	done := make(chan error, 1)
	go func() { done <- New("", "").Serve(context.Background(), "0.0.0.0:0") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("public bind without a token was accepted")
		}
		if !strings.Contains(err.Error(), "token") {
			t.Fatalf("error does not mention the token: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve kept listening on a public interface without a token")
	}
}

func TestNewTokenIsRandomAndUsable(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 48 || a == b {
		t.Fatalf("tokens = %q / %q", a, b)
	}
	fixture(t)
	h := New("", a).Handler()
	if rec := do(t, h, "GET", APIPrefix+"/programs", a); rec.Code != http.StatusOK {
		t.Fatalf("generated token rejected: %d", rec.Code)
	}
}

func TestCountLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	cases := []struct {
		body string
		want int
	}{
		{"", 0},
		{"a\n", 1},
		{"a\nb", 2},
		{"a\nb\n\n", 2},
	}
	for _, c := range cases {
		if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := countLines(path); got != c.want {
			t.Errorf("countLines(%q) = %d, want %d", c.body, got, c.want)
		}
	}
	if got := countLines(filepath.Join(dir, "missing")); got != 0 {
		t.Errorf("missing file = %d, want 0", got)
	}
}

func TestScopeViewRefusesEmptyScope(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KAI_HOME", home)
	dir := filepath.Join(home, "prose")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(`{"name":"prose","scope_verdict":"unknown"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := do(t, New("", "").Handler(), "GET", APIPrefix+"/programs/prose/scope?host=example.com", "")
	body := decode(t, rec)
	if body["verdict"] != "OUT" {
		t.Fatalf("verdict = %v (an empty scope must never read as in scope)", body["verdict"])
	}
	if !strings.Contains(fmt.Sprint(body["reason"]), "no in-scope rules") {
		t.Fatalf("reason = %v", body["reason"])
	}
}

// One program, two views. The card and `kai board` must report the same surface,
// which is exactly the bug that shipped a card saying "ends 0" beside a board
// saying 14k.
func TestSurfaceMatchesBoard(t *testing.T) {
	home := fixture(t)
	dir := filepath.Join(home, "demo")
	store := recon.NewStore("demo")
	now := time.Now()
	for _, h := range []string{"a.demo.example", "b.demo.example", "c.demo.example"} {
		store.Host(h, now)
	}
	for _, e := range []string{"/v1/orders", "/v1/users"} {
		store.Endpoint(e, now)
	}
	if err := store.Save(dir); err != nil {
		t.Fatal(err)
	}

	body := decode(t, do(t, New("", "").Handler(), "GET", APIPrefix+"/programs/demo", ""))
	surface, _ := body["surface"].(map[string]any)
	if surface["hosts"] != float64(3) || surface["endpoints"] != float64(2) {
		t.Fatalf("api surface = %v", surface)
	}
	if surface["last_recon"] == nil || surface["last_recon"] == "" {
		t.Fatalf("api surface has no last_recon: %v", surface)
	}

	report, err := board.Snapshot(home)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range report.Programs {
		if p.Name != "demo" {
			continue
		}
		found = true
		if p.Hosts != int(surface["hosts"].(float64)) || p.Endpoints != int(surface["endpoints"].(float64)) {
			t.Fatalf("board says hosts %d/ends %d, api says %v", p.Hosts, p.Endpoints, surface)
		}
		if p.LastRecon != surface["last_recon"] {
			t.Fatalf("board last_recon %q, api %v", p.LastRecon, surface["last_recon"])
		}
	}
	if !found {
		t.Fatal("board does not list demo")
	}
}

// Port 0 is how an operator avoids a collision; the printed address has to be
// the one the kernel actually bound.
func TestListenReportsPickedPort(t *testing.T) {
	fixture(t)
	s := New("", "")
	ln, err := s.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if _, port, _ := net.SplitHostPort(addr); port == "0" || port == "" {
		t.Fatalf("listener reported port %q", port)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.ServeListener(ctx, ln) }()

	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("bound address is not serving: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("ServeListener = %v", err)
	}
}

// A bare "data" home depends on the working directory, so the service must
// report and use an absolute root.
func TestHomeRootIsAbsolute(t *testing.T) {
	restore := func(key, old string, had bool) {
		if had {
			_ = os.Setenv(key, old)
		}
	}
	for _, key := range []string{"KAI_HOME", "BOUNTYKIT_HOME"} {
		old, had := os.LookupEnv(key)
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
		defer restore(key, old, had)
	}
	root := New("", "").HomeRoot()
	if !filepath.IsAbs(root) {
		t.Fatalf("HomeRoot = %q, want an absolute path", root)
	}
	if filepath.Base(root) != "data" {
		t.Fatalf("HomeRoot = %q, want it to end in data", root)
	}
}
