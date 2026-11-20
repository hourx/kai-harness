package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureIsDeterministicAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	raw := []byte("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"orders\":[]}")
	it := Item{
		TS:     "2026-01-01T00:00:00Z",
		Kind:   "response",
		Host:   "api.example.com",
		Method: "GET",
		Path:   "/v1/orders",
		Status: 200,
	}
	first, existed, err := Capture(dir, it, raw, "orders.json")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if existed {
		t.Fatal("first capture reported an existing record")
	}
	second, existed, err := Capture(dir, it, raw, "orders.json")
	if err != nil {
		t.Fatalf("second capture: %v", err)
	}
	if !existed {
		t.Fatal("capturing identical bytes twice should be an idempotent no-op")
	}
	if first.ID != second.ID {
		t.Fatalf("id not deterministic: %s vs %s", first.ID, second.ID)
	}
	items, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 indexed item, got %d", len(items))
	}
	if first.BodySHA256 == "" || first.BodySHA256 != first.BlobSHA256 {
		t.Fatalf("body hash missing or mismatched: body=%q blob=%q", first.BodySHA256, first.BlobSHA256)
	}
	want := filepath.Join("evidence", first.ID+"-orders.json")
	if first.Blob != want {
		t.Fatalf("blob path: want %s, got %s", want, first.Blob)
	}
	assertPerm(t, filepath.Join(dir, first.Blob), 0o600)
	assertPerm(t, IndexPath(dir), 0o600)
}

func TestCaptureRejectsIncompleteItems(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		item Item
	}{
		{"no kind", Item{Host: "a.example.com"}},
		{"unknown kind", Item{Kind: "guess", Host: "a.example.com"}},
		{"no identity", Item{Kind: "response"}},
	}
	for _, tc := range cases {
		if _, _, err := Capture(dir, tc.item, nil, ""); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}

func TestAttachAndFind(t *testing.T) {
	dir := t.TempDir()
	it, _, err := Capture(dir, Item{Kind: "note", Note: "triager asked for a second account"}, nil, "")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	got, err := Attach(dir, it.ID, "F-001")
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if got.Finding != "F-001" {
		t.Fatalf("finding not linked: %q", got.Finding)
	}
	back, ok, err := Find(dir, it.ID)
	if err != nil || !ok || back.Finding != "F-001" {
		t.Fatalf("link did not survive a reload: ok=%v err=%v link=%q", ok, err, back.Finding)
	}
	if _, err := Attach(dir, "deadbeef", "F-002"); err == nil {
		t.Fatal("attaching an unknown id should fail")
	}
}

func TestMarkdownListsHashes(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Capture(dir, Item{Kind: "log", Host: "a.example.com", Path: "/x", TS: "2026-01-02T00:00:00Z"}, []byte("x"), "x.log"); err != nil {
		t.Fatalf("capture: %v", err)
	}
	items, _ := Load(dir)
	md := Markdown(items)
	for _, want := range []string{"sha256:", "log", "a.example.com/x"} {
		if !contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Fatalf("%s: want mode %o, got %o", path, want, got)
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
