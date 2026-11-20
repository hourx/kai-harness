package serve

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hourx/kai-harness/pkg/progress"
)

// watchServer builds a workspace with one program in a temp home and returns the
// watch URL for it plus the program directory.
func watchServer(t *testing.T, backlog string) (string, string) {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, "demo")
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(`{"name":"demo"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := New(home, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	url := ts.URL + APIPrefix + "/programs/demo/watch"
	if backlog != "" {
		url += "?backlog=" + backlog
	}
	return url, dir
}

// readFrames reads SSE data frames until it has want of them or the deadline
// passes. The reader is closed by the caller through cancel.
func readFrames(t *testing.T, r *bufio.Reader, want int, deadline time.Duration) []map[string]any {
	t.Helper()
	var out []map[string]any
	stop := time.Now().Add(deadline)
	for len(out) < want && time.Now().Before(stop) {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if !strings.HasPrefix(line, "data: ") {
			continue // comment/keepalive or blank separator
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &m); err != nil {
			t.Fatalf("frame is not JSON: %q", line)
		}
		out = append(out, m)
	}
	return out
}

func writeRecorded(t *testing.T, dir string, evs ...progress.Event) {
	t.Helper()
	rec, err := progress.NewRecorder(filepath.Join(dir, ProgressFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		rec.Write(e)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWatchReplaysTheBacklogThenFollows(t *testing.T) {
	url, dir := watchServer(t, "")
	writeRecorded(t, dir,
		progress.Event{At: time.Unix(1, 0).UTC(), Kind: progress.KindPhase, Phase: "discover", Text: "start"},
		progress.Event{At: time.Unix(2, 0).UTC(), Kind: progress.KindCounts, Phase: "discover", Text: "214 hosts", Counts: map[string]int{"discovered": 214}},
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q", ct)
	}
	r := bufio.NewReader(resp.Body)
	got := readFrames(t, r, 2, 5*time.Second)
	if len(got) != 2 {
		t.Fatalf("backlog frames = %d, want 2", len(got))
	}
	if got[0]["Text"] != "start" || got[1]["Phase"] != "discover" {
		t.Errorf("backlog order wrong: %v", got)
	}
	if n, _ := got[1]["Counts"].(map[string]any)["discovered"].(float64); n != 214 {
		t.Errorf("counts did not survive the stream: %v", got[1])
	}

	// A line written after the stream started must arrive.
	rec, err := progress.NewRecorder(filepath.Join(dir, ProgressFile))
	if err != nil {
		t.Fatal(err)
	}
	rec.Write(progress.Event{At: time.Unix(3, 0).UTC(), Kind: progress.KindDone, Phase: "discover", Text: "done"})
	rec.Close()

	more := readFrames(t, r, 1, 5*time.Second)
	if len(more) != 1 || more[0]["Text"] != "done" {
		t.Fatalf("follow frames = %v, want the appended event", more)
	}
}

func TestWatchBacklogZeroSkipsThePast(t *testing.T) {
	url, dir := watchServer(t, "0")
	writeRecorded(t, dir,
		progress.Event{At: time.Unix(1, 0).UTC(), Kind: progress.KindLog, Text: "before connection"},
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	r := bufio.NewReader(resp.Body)
	// Drain the greeting comment so the reader is positioned at the stream.
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	// Let the watcher take its position at the end of the file before anything
	// is appended; the first frame after this must be the new event, never the
	// one recorded before the connection.
	time.Sleep(2 * watchPoll)

	rec, err := progress.NewRecorder(filepath.Join(dir, ProgressFile))
	if err != nil {
		t.Fatal(err)
	}
	rec.Write(progress.Event{At: time.Unix(9, 0).UTC(), Kind: progress.KindLog, Text: "after connection"})
	rec.Close()

	got := readFrames(t, r, 1, 5*time.Second)
	if len(got) != 1 || got[0]["Text"] != "after connection" {
		t.Fatalf("frames = %v, want only the event written after the connection", got)
	}
}

func TestWatchOnAMissingFileWaitsInsteadOfFailing(t *testing.T) {
	url, _ := watchServer(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 while waiting for a run to start", resp.StatusCode)
	}
}

// TestWatchOutlivesTheWriteTimeout pins the live-fire finding: a real server
// arms a write deadline per request, and a stream that never clears it is cut
// off mid-run. The client here does nothing wrong — it connects, waits past
// WriteTimeout, and only then is the event written.
func TestWatchOutlivesTheWriteTimeout(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "demo")
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(`{"name":"demo"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := New(home, "")
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.Config.WriteTimeout = 400 * time.Millisecond
	ts.Start()
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		ts.URL+APIPrefix+"/programs/demo/watch?backlog=0", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	r := bufio.NewReader(resp.Body)
	if _, err := r.ReadString('\n'); err != nil { // greeting
		t.Fatal(err)
	}

	time.Sleep(3 * ts.Config.WriteTimeout) // outlive the deadline the server armed

	rec, err := progress.NewRecorder(filepath.Join(dir, ProgressFile))
	if err != nil {
		t.Fatal(err)
	}
	rec.Write(progress.Event{At: time.Unix(5, 0).UTC(), Kind: progress.KindLog, Text: "after the deadline"})
	rec.Close()

	got := readFrames(t, r, 1, 5*time.Second)
	if len(got) != 1 || got[0]["Text"] != "after the deadline" {
		t.Fatalf("frames after WriteTimeout = %v, want the event the run wrote", got)
	}
}

func TestWatchUnknownProgramIs404(t *testing.T) {
	home := t.TempDir()
	srv := New(home, "")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + APIPrefix + "/programs/nope/watch")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestWatchIsNotAWritePath(t *testing.T) {
	url, dir := watchServer(t, "")
	rec, err := progress.NewRecorder(filepath.Join(dir, ProgressFile))
	if err != nil {
		t.Fatal(err)
	}
	rec.Write(progress.Event{At: time.Unix(1, 0).UTC(), Kind: progress.KindLog, Text: "only this"})
	rec.Close()
	before := lineCount(t, filepath.Join(dir, ProgressFile))

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(resp.Body)
	readFrames(t, r, 1, 5*time.Second)
	cancel()
	resp.Body.Close()

	if after := lineCount(t, filepath.Join(dir, ProgressFile)); after != before {
		t.Fatalf("the watcher changed the recorded run: %d → %d lines", before, after)
	}
}

func lineCount(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	return strings.Count(string(b), "\n")
}
