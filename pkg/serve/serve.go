// Package serve is kai's service face: the same read-only state the CLI prints,
// exposed over HTTP and JSON, so a UI can be built without shelling out.
//
// It is read-only by construction. Every handler reads files under the workspace
// root; none of them runs a command or writes an artifact. An exposed port
// therefore cannot become a remote scan surface — mutations stay in the CLI,
// where the operator is the one holding the terminal.
//
// The default bind is loopback. Binding anywhere else requires a bearer token,
// and that check runs before the listener opens, so a misconfigured start fails
// loudly instead of quietly serving a campaign to the network.
package serve

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hourx/kai-harness/pkg/board"
	"github.com/hourx/kai-harness/pkg/evidence"
	"github.com/hourx/kai-harness/pkg/hypothesis"
	"github.com/hourx/kai-harness/pkg/outcome"
	"github.com/hourx/kai-harness/pkg/program"
	"github.com/hourx/kai-harness/pkg/recon"
	"github.com/hourx/kai-harness/pkg/scope"
	"github.com/hourx/kai-harness/pkg/surface"
	"github.com/hourx/kai-harness/pkg/triage"
	"github.com/hourx/kai-harness/pkg/version"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// APIPrefix is the base path of the JSON API.
const APIPrefix = "/api/v1"

// DefaultAddr keeps the workspace on this machine. The port is a suggestion:
// --addr 127.0.0.1:0 asks the kernel for a free one.
const DefaultAddr = "127.0.0.1:8789"

const (
	defaultQueueLimit = 20
	maxQueueLimit     = 500
	recentOutcomes    = 10
)

// Server answers HTTP requests from the workspace on disk.
type Server struct {
	Home  string // workspace root; empty means workspace.Home()
	Token string // empty means no auth, which is only allowed on loopback
	Clock func() time.Time
}

// New builds a server. An empty home resolves to workspace.Home() per request,
// so a caller that sets KAI_HOME late still gets the right root.
func New(home, token string) *Server {
	return &Server{Home: home, Token: token, Clock: time.Now}
}

func (s *Server) root() string {
	if s.Home != "" {
		return s.Home
	}
	return absHome()
}

// absHome makes the workspace root absolute. The bare fallback is "data", which
// means different directories depending on where the process started, and a
// service that reports the wrong root is worse than one that reports none.
func absHome() string {
	h := workspace.Home()
	if abs, err := filepath.Abs(h); err == nil {
		return abs
	}
	return h
}

// HomeRoot reports the workspace root this server reads, resolved the same way
// every handler resolves it.
func (s *Server) HomeRoot() string { return s.root() }

func (s *Server) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

// NewToken returns a bearer token for `--token auto`.
func NewToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// IsLoopback reports whether a bind host stays on this machine. An empty host
// means "every interface", which is not loopback.
func IsLoopback(host string) bool {
	h := strings.ToLower(strings.Trim(host, "[]"))
	switch h {
	case "", "*", "0.0.0.0", "::":
		return false
	case "localhost":
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// ValidateAddr refuses a bind that would expose the workspace without a token.
func ValidateAddr(addr, token string) error {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("bad address %q: %w", addr, err)
	}
	host, _, _ := net.SplitHostPort(addr)
	if IsLoopback(host) {
		return nil
	}
	if token == "" {
		return fmt.Errorf("refusing to bind %s without a token: pass --token auto or set KAI_SERVE_TOKEN", addr)
	}
	return nil
}

// Listen binds addr after validating it. Binding is separated from serving so a
// caller that passes port 0 can read the port the kernel picked.
func (s *Server) Listen(addr string) (net.Listener, error) {
	if err := ValidateAddr(addr, s.Token); err != nil {
		return nil, err
	}
	return net.Listen("tcp", addr)
}

// Serve listens on addr until ctx is cancelled. A cancelled context is not an
// error.
func (s *Server) Serve(ctx context.Context, addr string) error {
	ln, err := s.Listen(addr)
	if err != nil {
		return err
	}
	return s.ServeListener(ctx, ln)
}

// ServeListener serves an already-bound listener until ctx is cancelled.
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		close(done)
	}()
	err := srv.Serve(ln)
	<-done
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Handler returns the router. Exported for tests and for embedding.
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.route) }

func (s *Server) authorized(r *http.Request) bool {
	if s.Token == "" {
		return true
	}
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	// Compare digests so the check leaks neither length nor prefix.
	got := sha256.Sum256([]byte(strings.TrimPrefix(header, prefix)))
	want := sha256.Sum256([]byte(s.Token))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == "" {
		path = "/"
	}
	if path == "/healthz" {
		s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version.String()})
		return
	}
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="kai"`)
		s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid token"})
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		s.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"error": "read-only service: " + r.Method + " is not allowed",
		})
		return
	}

	switch {
	case path == "/":
		s.dashboard(w)
	case path == APIPrefix+"/board":
		rep, err := board.Snapshot(s.root())
		if err != nil {
			s.fail(w, http.StatusInternalServerError, err)
			return
		}
		s.writeJSON(w, http.StatusOK, rep)
	case path == APIPrefix+"/programs":
		views, err := s.programs()
		if err != nil {
			s.fail(w, http.StatusInternalServerError, err)
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"home": s.root(), "programs": views})
	default:
		if name, sub, ok := splitProgramPath(path); ok {
			s.programRoute(w, r, name, sub)
			return
		}
		s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such route: " + path})
	}
}

// splitProgramPath turns /api/v1/programs/<name>[/<sub>] into its parts.
func splitProgramPath(path string) (name, sub string, ok bool) {
	prefix := APIPrefix + "/programs/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(path, prefix)
	if rest == "" {
		return "", "", false
	}
	if i := strings.Index(rest, "/"); i >= 0 {
		return rest[:i], strings.Trim(rest[i+1:], "/"), true
	}
	return rest, "", true
}

func (s *Server) programRoute(w http.ResponseWriter, r *http.Request, name, sub string) {
	if err := workspace.ValidateName(name); err != nil {
		s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown program: " + name})
		return
	}
	dir := filepath.Join(s.root(), name)
	if _, err := os.Stat(filepath.Join(dir, "meta.json")); err != nil {
		s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown program: " + name})
		return
	}
	limit := queueLimit(r)

	switch sub {
	case "":
		view, err := s.view(name, dir, limit)
		if err != nil {
			s.fail(w, http.StatusInternalServerError, err)
			return
		}
		if host := strings.TrimSpace(r.URL.Query().Get("host")); host != "" {
			view.Scope.check(host)
		}
		s.writeJSON(w, http.StatusOK, view)
	case "queue":
		q, err := s.queue(dir, limit)
		if err != nil {
			s.fail(w, http.StatusInternalServerError, err)
			return
		}
		s.writeJSON(w, http.StatusOK, q)
	case "plan":
		pl, err := s.plan(dir)
		if err != nil {
			s.fail(w, http.StatusInternalServerError, err)
			return
		}
		s.writeJSON(w, http.StatusOK, pl)
	case "brief":
		text, err := program.CompactBrief(dir)
		if err != nil {
			s.fail(w, http.StatusNotFound, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, text)
	case "evidence":
		items, err := evidence.Load(dir)
		if err != nil {
			s.fail(w, http.StatusInternalServerError, err)
			return
		}
		evidence.Sort(items)
		s.writeJSON(w, http.StatusOK, map[string]any{"total": len(items), "items": items})
	case "outcomes":
		s.writeJSON(w, http.StatusOK, s.outcomes(dir))
	case "scope":
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		if host == "" {
			s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "usage: ?host=<name or ip>"})
			return
		}
		sv := s.scopeView(dir)
		sv.check(host)
		s.writeJSON(w, http.StatusOK, sv)
	default:
		s.writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such route: " + sub})
	}
}

func queueLimit(r *http.Request) int {
	limit := defaultQueueLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxQueueLimit {
		limit = maxQueueLimit
	}
	return limit
}

// ---------------------------------------------------------------- view models

type programView struct {
	Name      string           `json:"name"`
	Dir       string           `json:"dir"`
	Platform  string           `json:"platform,omitempty"`
	Program   string           `json:"program_url,omitempty"`
	Verdict   string           `json:"scope_verdict"`
	Updated   string           `json:"updated_at,omitempty"`
	Surface   surfaceView      `json:"surface"`
	Artifacts map[string]int   `json:"artifacts"`
	Scope     scopeView        `json:"scope"`
	Queue     queueView        `json:"queue"`
	Plan      *hypothesis.Plan `json:"plan,omitempty"`
	Findings  findingsView     `json:"findings"`
	Evidence  int              `json:"evidence"`
	Outcomes  outcomesView     `json:"outcomes"`
}

// surfaceView mirrors what `kai board` counts, so the card and the board never
// disagree about how big a program's surface is. The artifacts map stays the raw
// line counts of the workspace files, which is a different (and older) measure.
type surfaceView struct {
	Hosts     int    `json:"hosts"`
	Endpoints int    `json:"endpoints"`
	LastRecon string `json:"last_recon,omitempty"`
}

type scopeView struct {
	In      int      `json:"in_rules"`
	Out     int      `json:"out_rules"`
	InList  []string `json:"in_sample,omitempty"`
	OutList []string `json:"out_sample,omitempty"`
	Note    string   `json:"note,omitempty"`
	Host    string   `json:"host,omitempty"`
	Verdict string   `json:"verdict,omitempty"` // IN or OUT, only when a host is asked about
	Reason  string   `json:"reason,omitempty"`
}

func (v *scopeView) check(host string) {
	v.Host = host
	target, err := scope.Parse(host)
	if err != nil {
		v.Verdict = "OUT"
		v.Reason = "unparseable target: " + err.Error()
		return
	}
	if v.Note != "" && v.In == 0 {
		v.Verdict = "OUT"
		v.Reason = v.Note
		return
	}
	gate := scope.Gate{In: v.InList, Out: v.OutList}
	if len(gate.In) == 0 {
		v.Verdict = "OUT"
		v.Reason = "no in-scope rules (kai exports scope.txt from the policy; it never guesses)"
		return
	}
	ok, reason := gate.Check(target)
	if ok {
		v.Verdict = "IN"
	} else {
		v.Verdict = "OUT"
	}
	v.Reason = reason
}

type queueView struct {
	Generated string               `json:"generated,omitempty"`
	Total     int                  `json:"total"`
	Clusters  int                  `json:"clusters,omitempty"`
	Limit     int                  `json:"limit"`
	Items     []surface.Hypothesis `json:"items"`
}

type findingsView struct {
	Total    int              `json:"total"`
	ByStatus map[string]int   `json:"by_status,omitempty"`
	Items    []triage.Finding `json:"items,omitempty"`
}

type outcomesView struct {
	Total    int              `json:"total"`
	ByStatus map[string]int   `json:"by_status,omitempty"`
	Recent   []outcome.Record `json:"recent,omitempty"`
}

// ------------------------------------------------------------------ assemblers

func (s *Server) programs() ([]programView, error) {
	names, err := workspace.List()
	if err != nil {
		return nil, err
	}
	out := make([]programView, 0, len(names))
	for _, name := range names {
		dir := filepath.Join(s.root(), name)
		view, err := s.view(name, dir, 0)
		if err != nil {
			// A program with an unreadable meta is still listed, so the operator
			// can see it on the dashboard instead of silently losing a workspace.
			out = append(out, programView{Name: name, Dir: dir, Verdict: "unreadable", Artifacts: map[string]int{}})
			continue
		}
		view.Queue.Items = nil // the list stays light; the detail carries the queue
		out = append(out, view)
	}
	return out, nil
}

func (s *Server) view(name, dir string, limit int) (programView, error) {
	meta, err := readMeta(dir)
	if err != nil {
		return programView{}, err
	}
	findings := s.findings(dir)
	queue, err := s.queue(dir, limit)
	if err != nil {
		return programView{}, err
	}
	pl, err := s.plan(dir)
	if err != nil {
		return programView{}, err
	}
	view := programView{
		Name:      name,
		Dir:       dir,
		Platform:  meta.Platform,
		Program:   meta.ProgramURL,
		Verdict:   meta.ScopeVerdict,
		Updated:   meta.UpdatedAt.UTC().Format(time.RFC3339),
		Surface:   surfaceStats(dir, name),
		Artifacts: artifacts(dir),
		Scope:     s.scopeView(dir),
		Queue:     queue,
		Plan:      &pl,
		Findings:  findings,
		Evidence:  len(evidenceItems(dir)),
		Outcomes:  s.outcomes(dir),
	}
	if view.Updated == "0001-01-01T00:00:00Z" {
		view.Updated = ""
	}
	return view, nil
}

// surfaceStats reads the same recon store `kai board` reads. If the store is
// missing the counts stay zero rather than falling back to the legacy text
// files, because a number that comes from a different source is worse than no
// number: two views of one program would disagree.
func surfaceStats(dir, name string) surfaceView {
	var v surfaceView
	if store, err := recon.LoadStore(dir, name); err == nil && store != nil {
		v.Hosts = len(store.Hosts)
		v.Endpoints = len(store.Endpoints)
	}
	if ts := newestModTime(dir, "assets.json", "map.json"); !ts.IsZero() {
		v.LastRecon = ts.UTC().Format(time.RFC3339)
	}
	return v
}

// newestModTime reports the most recent modification time among files that
// exist, treating a missing set as zero.
func newestModTime(dir string, names ...string) time.Time {
	var newest time.Time
	for _, n := range names {
		info, err := os.Stat(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest
}

func readMeta(dir string) (workspace.Meta, error) {
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return workspace.Meta{}, err
	}
	var m workspace.Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return workspace.Meta{}, err
	}
	return m, nil
}

// artifacts counts the lines of every artifact kai knows about. A missing file
// counts as 0, which is the same thing `kai status` prints.
func artifacts(dir string) map[string]int {
	out := make(map[string]int, len(workspace.ArtifactNames))
	for _, name := range workspace.ArtifactNames {
		out[name] = countLines(filepath.Join(dir, name))
	}
	return out
}

func countLines(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	if len(b) == 0 {
		return 0
	}
	n := len(strings.Split(strings.TrimRight(string(b), "\n"), "\n"))
	return n
}

func (s *Server) queue(dir string, limit int) (queueView, error) {
	pl, err := surface.LoadPlan(dir)
	if err != nil {
		// No recon yet is a normal state, not a service error.
		return queueView{Items: []surface.Hypothesis{}}, nil
	}
	view := queueView{Generated: pl.Generated, Total: len(pl.Items), Clusters: len(pl.Clusters), Limit: limit, Items: []surface.Hypothesis{}}
	if limit > 0 {
		for i, item := range pl.Items {
			if i >= limit {
				break
			}
			view.Items = append(view.Items, item)
		}
	}
	return view, nil
}

// plan rebuilds the waves from the queue. Build is pure, so the service never
// writes plan.json behind the operator's back.
func (s *Server) plan(dir string) (hypothesis.Plan, error) {
	p, err := surface.LoadPlan(dir)
	if err != nil {
		return hypothesis.Plan{}, nil
	}
	return hypothesis.Build(p), nil
}

func (s *Server) findings(dir string) findingsView {
	out := findingsView{ByStatus: map[string]int{}}
	led, err := triage.Load(dir)
	if err != nil || led == nil {
		return out
	}
	out.Items = led.Findings
	out.Total = len(led.Findings)
	for _, f := range led.Findings {
		out.ByStatus[f.Status]++
	}
	if len(out.Items) == 0 {
		out.Items = nil
	}
	return out
}

func evidenceItems(dir string) []evidence.Item {
	items, err := evidence.Load(dir)
	if err != nil {
		return nil
	}
	evidence.Sort(items)
	return items
}

func (s *Server) outcomes(dir string) outcomesView {
	out := outcomesView{ByStatus: map[string]int{}}
	table, err := outcome.Load(dir)
	if err != nil || table == nil {
		return out
	}
	records := table.Records()
	out.Total = table.Len()
	for _, rec := range records {
		out.ByStatus[rec.Status]++
	}
	if len(records) > recentOutcomes {
		records = records[len(records)-recentOutcomes:]
	}
	out.Recent = records
	return out
}

func (s *Server) scopeView(dir string) scopeView {
	v := scopeView{}
	in, err := scope.Load(filepath.Join(dir, "scope.txt"))
	if err != nil {
		v.Note = err.Error()
	} else {
		v.In = len(in)
		v.InList = sample(in)
	}
	out, err := scope.Load(filepath.Join(dir, "out-of-scope.txt"))
	if err != nil {
		if v.Note == "" {
			v.Note = err.Error()
		}
	} else {
		v.Out = len(out)
		v.OutList = sample(out)
	}
	return v
}

// sample keeps the payload small: rules can run to hundreds of lines, and the
// dashboard only needs enough to recognise the program.
func sample(rules []string) []string {
	const n = 10
	if len(rules) <= n {
		return rules
	}
	return rules[:n]
}

// ---------------------------------------------------------------------- output

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func (s *Server) fail(w http.ResponseWriter, status int, err error) {
	s.writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) dashboard(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, dashboardHTML)
}
