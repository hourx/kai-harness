package progress

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecorderRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "progress.jsonl")
	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []Event{
		{At: time.Unix(1, 0).UTC(), Kind: KindPhase, Phase: "discover", Text: "start"},
		{At: time.Unix(2, 0).UTC(), Kind: KindCounts, Phase: "discover", Text: "214 hosts", Counts: map[string]int{"discovered": 214}},
	}
	for _, e := range want {
		rec.Write(e)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("read %d events, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Kind != want[i].Kind || got[i].Text != want[i].Text || got[i].Phase != want[i].Phase {
			t.Errorf("event %d = %+v, want %+v", i, got[i], want[i])
		}
		if !got[i].At.Equal(want[i].At) {
			t.Errorf("event %d time = %s, want %s", i, got[i].At, want[i].At)
		}
	}
	if got[1].Counts["discovered"] != 214 {
		t.Errorf("counters did not survive: %v", got[1].Counts)
	}
}

// A run truncates the file: a watcher that mixed two runs would report the
// wrong one.
func TestRecorderTruncatesOnANewRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.jsonl")
	first, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	first.Write(Event{At: time.Unix(1, 0).UTC(), Kind: KindLog, Text: "run one"})
	first.Close()

	second, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	second.Write(Event{At: time.Unix(2, 0).UTC(), Kind: KindLog, Text: "run two"})
	second.Close()

	got, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Text != "run two" {
		t.Fatalf("recorded %v, want only the second run", got)
	}
}

func TestRecorderFileIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.jsonl")
	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	rec.Write(Event{Kind: KindLog, Text: "x"})
	rec.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

// A line a reader caught mid-write must be skipped, not treated as a failure.
func TestReadFileSkipsPartialLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.jsonl")
	body := `{"At":"2026-11-20T10:00:00Z","Kind":"log","Text":"complete"}` + "\n" +
		`{"At":"2026-11-20T10:00:01Z","Kind":"log","Tex` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Text != "complete" {
		t.Fatalf("read %v, want the one complete line", got)
	}
}

func TestRecordSubscribesToTheBus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.jsonl")
	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	bus := NewBus(16)
	stop := Record(bus, rec)
	for i := 0; i < 3; i++ {
		bus.Emit(Event{Kind: KindLog, Text: "line"})
	}
	stop() // must flush and close, so the file is complete when it returns

	got, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("recorded %d events, want 3", len(got))
	}
}
