package outcome

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidAndYields(t *testing.T) {
	if !Valid("negation") || Valid("nope") {
		t.Error("Valid does not accept exactly the documented set")
	}
	for _, s := range Statuses {
		want := s == StatusFinding || s == StatusReported || s == StatusPaid
		if Yields(s) != want {
			t.Errorf("Yields(%q) = %v, want %v", s, Yields(s), want)
		}
	}
}

func TestNormalizeKeepsMethodForm(t *testing.T) {
	cases := map[string]string{
		"GET /api/users/1": "GET /api/users/1",
		"  GET   /api/x  ": "GET /api/x",
		"api.example.com":  "api.example.com",
		"POST /login":      "POST /login",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTableLastWins(t *testing.T) {
	tbl := NewTable(
		Record{TS: "2026-01-01T00:00:00Z", Target: "GET /a", Status: StatusNegation},
		Record{TS: "2026-01-02T00:00:00Z", Target: "GET /a", Status: StatusFinding},
	)
	r, ok := tbl.Last("get /a")
	if !ok || r.Status != StatusFinding {
		t.Fatalf("Last = %+v, %v; want the newest record (case-insensitive key)", r, ok)
	}
	if tbl.Len() != 1 {
		t.Errorf("Len = %d, want 1", tbl.Len())
	}
}

func TestAppendAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := Append(dir, Record{Target: "GET /x", Status: StatusNegation, Note: "401, no data"}); err != nil {
		t.Fatal(err)
	}
	if err := Append(dir, Record{Target: "GET /y", Status: StatusInformational}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("outcomes.jsonl mode = %o, want 600", perm)
	}
	tbl, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if tbl.Len() != 2 {
		t.Fatalf("Len = %d, want 2", tbl.Len())
	}
	r, _ := tbl.Last("GET /x")
	if r.Note != "401, no data" || r.TS == "" {
		t.Errorf("round trip lost fields: %+v", r)
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	tbl, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("missing file must not be an error: %v", err)
	}
	if tbl.Len() != 0 {
		t.Errorf("Len = %d, want 0", tbl.Len())
	}
}

func TestLoadRejectsCorruptLine(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(dir), []byte("{not json}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("a corrupt log must fail loudly, not read as empty")
	}
}

func TestFreshHandlesSameSecondRecords(t *testing.T) {
	surface := time.Date(2026, 3, 2, 0, 0, 0, 700_000_000, time.UTC)
	// A record written with second precision in the same second must be fresh:
	// truncation alone must never make an outcome look older than the surface.
	r := Record{TS: "2026-03-02T00:00:00Z", Target: "GET /a", Status: StatusNegation}
	if !Fresh(r, surface) {
		t.Error("same-second record reported stale")
	}
	older := Record{TS: "2026-03-01T23:59:58Z", Target: "GET /a"}
	if Fresh(older, surface) {
		t.Error("record two seconds before the surface reported fresh")
	}
	if Fresh(Record{TS: "garbage", Target: "GET /a"}, surface) {
		t.Error("unparseable timestamp must count as stale")
	}
}

func TestSurfaceTSReadsArtifacts(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-48 * time.Hour)
	store := filepath.Join(dir, "assets.json")
	if err := os.WriteFile(store, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(store, old, old); err != nil {
		t.Fatal(err)
	}
	if got := SurfaceTS(dir); !got.Equal(old.UTC()) {
		t.Errorf("SurfaceTS = %v, want %v", got, old.UTC())
	}
	if got := SurfaceTS(t.TempDir()); !got.IsZero() {
		t.Errorf("SurfaceTS with no artifacts = %v, want zero time", got)
	}
}
