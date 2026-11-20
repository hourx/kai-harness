package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The token is assembled at run time: a literal that looks like a live key gets
// scrubbed by secret scanners on the way to disk, which would silently weaken
// the very assertion this fixture exists to make.
const harToken = "tok" + "_" + "example123456"

var sampleHAR = fmt.Sprintf(`{
  "log": {
    "version": "1.2",
    "creator": {"name": "kai-test", "version": "1"},
    "entries": [
      {
        "startedDateTime": "2026-11-20T10:00:00Z",
        "request": {
          "method": "get",
          "url": "https://api.example.test/v1/orders?page=1",
          "headers": [{"name": "Authorization", "value": "Bearer %s"}]
        },
        "response": {
          "status": 200,
          "headers": [{"name": "Content-Type", "value": "application/json"}],
          "content": {"size": 42, "text": "{\"ok\":true}"}
        }
      },
      {
        "startedDateTime": "2026-11-20T10:00:01Z",
        "request": {"method": "GET", "url": "chrome-extension://abc/x.js", "headers": []},
        "response": {"status": 0, "headers": [], "content": {}}
      },
      {
        "startedDateTime": "2026-11-20T10:00:02Z",
        "request": {
          "method": "POST",
          "url": "https://api.example.test/v1/orders",
          "headers": [{"name": "Cookie", "value": "sid=1"}],
          "postData": {"mimeType": "application/json", "text": "{\"item\":1}"}
        },
        "response": {"status": 403, "headers": [], "content": {}}
      }
    ]
  }
}`, harToken)

func TestHAREntriesPairRequestWithResponse(t *testing.T) {
	items, st, err := HAREntries([]byte(sampleHAR), HAROptions{Redact: true, Label: "capture.har"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Entries != 3 || st.Kept != 2 || st.Skipped != 1 {
		t.Fatalf("stats = %+v", st)
	}
	if st.Why["non-http scheme"] != 1 {
		t.Errorf("skip reason not recorded: %+v", st.Why)
	}
	if st.Version != "1.2" || st.Creator != "kai-test" {
		t.Errorf("capture identity lost: %+v", st)
	}

	first := items[0].Item
	if first.Method != "GET" {
		t.Errorf("method = %q, want GET (HAR stores it lower-case)", first.Method)
	}
	if first.Host != "api.example.test" || first.Path != "/v1/orders?page=1" {
		t.Errorf("host/path = %q %q", first.Host, first.Path)
	}
	if first.Status != 200 || first.Kind != "response" {
		t.Errorf("status/kind = %d %q", first.Status, first.Kind)
	}
	if !strings.Contains(strings.Join(first.Headers, "|"), "req:Authorization: REDACTED(len=") {
		t.Errorf("request header not redacted: %v", first.Headers)
	}
	if !strings.Contains(strings.Join(first.Headers, "|"), "res:Content-Type: application/json") {
		t.Errorf("response header missing: %v", first.Headers)
	}
	if len(items[0].Raw) == 0 {
		t.Error("item carries no bytes")
	}
	// Both sides must live in the blob, not only the response — and with
	// redaction on, the stored bytes must not keep the secret the index hides.
	blob := string(items[0].Raw)
	if !strings.Contains(blob, "https://api.example.test/v1/orders?page=1") || !strings.Contains(blob, `\"ok\":true`) {
		t.Errorf("blob is missing one side of the exchange: %s", blob)
	}
	if strings.Contains(blob, harToken) {
		t.Errorf("redaction claimed but the blob still holds the token: %s", blob)
	}
	if !strings.Contains(blob, `"headers_redacted":true`) {
		t.Errorf("blob does not record that headers were redacted: %s", blob)
	}
	if !strings.Contains(items[0].Item.Note, "capture.har entry 1") {
		t.Errorf("note = %q", items[0].Item.Note)
	}

	if ts := items[0].Item.TS; ts != "2026-11-20T10:00:00Z" {
		t.Errorf("ts = %q, want the capture time", ts)
	}
	if got := items[1].Item.Status; got != 403 {
		t.Errorf("second kept entry status = %d", got)
	}
}

func TestHAREntriesKeepSecretsWhenAsked(t *testing.T) {
	items, _, err := HAREntries([]byte(sampleHAR), HAROptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(items[0].Item.Headers, "|"), "req:Authorization: Bearer "+harToken) {
		t.Errorf("--keep-secrets must leave the header intact: %v", items[0].Item.Headers)
	}
	if !strings.Contains(string(items[0].Raw), harToken) {
		t.Errorf("--keep-secrets must keep the token in the stored bytes")
	}
}

func TestHARLimit(t *testing.T) {
	items, st, err := HAREntries([]byte(sampleHAR), HAROptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || st.Kept != 1 || st.Why["limit reached"] != 2 {
		t.Fatalf("limit not honoured: items=%d stats=%+v", len(items), st)
	}
}

func TestHARRejectsNonCapture(t *testing.T) {
	if _, _, err := HAREntries([]byte(`{"hello":1}`), HAROptions{}); err == nil {
		t.Error("a JSON object without a log must be rejected")
	}
	if _, _, err := HAREntries([]byte(`not json`), HAROptions{}); err == nil {
		t.Error("invalid JSON must be rejected")
	}
}

func TestImportHARIsIdempotent(t *testing.T) {
	pDir := t.TempDir()
	st, err := ImportHAR(pDir, []byte(sampleHAR), "capture.har", HAROptions{Redact: true})
	if err != nil {
		t.Fatal(err)
	}
	if st.Added != 2 || st.Existing != 0 {
		t.Fatalf("first import = %+v", st)
	}
	again, err := ImportHAR(pDir, []byte(sampleHAR), "capture.har", HAROptions{Redact: true})
	if err != nil {
		t.Fatal(err)
	}
	if again.Added != 0 || again.Existing != 2 {
		t.Fatalf("re-import duplicated evidence: %+v", again)
	}
	items, err := Load(pDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("index holds %d items, want 2", len(items))
	}
	for _, it := range items {
		if it.Blob == "" || it.BlobSHA256 == "" {
			t.Errorf("item %s has no blob on disk: %+v", it.ID, it)
		}
	}
	// A second capture of the same requests at a different time is new evidence,
	// not a duplicate.
	other := strings.Replace(sampleHAR, "2026-11-20T10:00:00Z", "2026-11-21T10:00:00Z", 1)
	third, err := ImportHAR(pDir, []byte(other), "later.har", HAROptions{Redact: true})
	if err != nil {
		t.Fatal(err)
	}
	if third.Added != 1 {
		t.Errorf("a later capture must be kept as new evidence: %+v", third)
	}
}

func TestImportHARNamesTheBlobAfterTheCapture(t *testing.T) {
	pDir := t.TempDir()
	if _, err := ImportHAR(pDir, []byte(sampleHAR), "session.har", HAROptions{}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(pDir, dirName))
	if err != nil {
		t.Fatal(err)
	}
	var named int
	for _, e := range entries {
		if strings.Contains(e.Name(), "session.har.") && strings.HasSuffix(e.Name(), ".json") {
			named++
		}
	}
	if named != 2 {
		t.Errorf("blobs named after capture: %d, want 2", named)
	}
}

func TestMarkdownHARReportsTheCounts(t *testing.T) {
	_, st, err := HAREntries([]byte(sampleHAR), HAROptions{})
	if err != nil {
		t.Fatal(err)
	}
	md := MarkdownHAR(st, "capture.har")
	for _, want := range []string{"# HAR import: capture.har", "entries: 3", "kept: 2", "non-http scheme: 1"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}
