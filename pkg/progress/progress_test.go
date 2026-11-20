package progress

import (
	"strings"
	"sync"
	"testing"
)

func TestParseCounts(t *testing.T) {
	cases := []struct {
		line string
		want map[string]int
	}{
		{"subfinder                214 hosts  (/usr/bin/subfinder)", map[string]int{"discovered": 214}},
		{"  assetfinder            12 hosts  (/usr/bin/assetfinder)", map[string]int{"discovered": 12}},
		{"gated   12 in scope, probing 9", map[string]int{"gated": 12, "probing": 9}},
		{"resolved 7/9", map[string]int{"resolved": 7, "resolved_of": 9}},
		{"live     5 hosts responded", map[string]int{"live": 5}},
		{"urls   214 in-scope, bundles 31 (public JS, no session on external hosts)", map[string]int{"urls": 214, "bundles": 31}},
		{"nuclei  skipped (not installed)", nil},
		{"session  stored (2 cookies, 1 headers)", nil},
		{"", nil},
		{"   ", nil},
		{"gated nonsense here", nil},
		{"resolved x/9", nil},
	}
	for _, tc := range cases {
		got := ParseCounts(tc.line)
		if len(got) != len(tc.want) {
			t.Fatalf("ParseCounts(%q) = %v, want %v", tc.line, got, tc.want)
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Fatalf("ParseCounts(%q)[%s] = %d, want %d", tc.line, k, got[k], v)
			}
		}
	}
}

func TestBusHistoryIsBounded(t *testing.T) {
	b := NewBus(3)
	for i := 0; i < 10; i++ {
		b.Emit(Event{Kind: KindLog, Text: "line"})
	}
	if got := b.Len(); got != 3 {
		t.Fatalf("Len() = %d, want 3", got)
	}
	if got := len(b.History()); got != 3 {
		t.Fatalf("len(History()) = %d, want 3", got)
	}
}

func TestBusFanOutAndUnsubscribe(t *testing.T) {
	b := NewBus(4)
	ch1, cancel1 := b.Subscribe()
	ch2, _ := b.Subscribe()
	b.Emit(Event{Kind: KindPhase, Phase: "probe"})
	for i, ch := range []<-chan Event{ch1, ch2} {
		select {
		case e := <-ch:
			if e.Phase != "probe" || e.Kind != KindPhase {
				t.Fatalf("subscriber %d got %+v", i, e)
			}
			if e.At.IsZero() {
				t.Fatalf("subscriber %d: event was not timestamped", i)
			}
		default:
			t.Fatalf("subscriber %d received nothing", i)
		}
	}
	cancel1()
	b.Emit(Event{Kind: KindPhase, Phase: "harvest"})
	select {
	case e := <-ch2:
		if e.Phase != "harvest" {
			t.Fatalf("subscriber 2 got %+v", e)
		}
	default:
		t.Fatal("subscriber 2 missed an event after another unsubscribed")
	}
}

// A subscriber that never reads must not block the run that is emitting.
func TestBusDoesNotBlockOnSlowSubscriber(t *testing.T) {
	b := NewBus(8)
	b.Subscribe() // never read from
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5000; i++ {
			b.Emit(Event{Kind: KindLog, Text: "x"})
		}
		close(done)
	}()
	<-done
}

func TestConcurrentEmit(t *testing.T) {
	b := NewBus(64)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				b.Emit(Event{Kind: KindLog, Text: "concurrent"})
			}
		}()
	}
	wg.Wait()
	if got := b.Len(); got != 64 {
		t.Fatalf("Len() = %d, want 64", got)
	}
}

// Lines split across Write calls must not be lost or doubled.
func TestWriterSplitsChunkedLines(t *testing.T) {
	b := NewBus(16)
	w := NewWriter(b)
	w.SetPhase("discover")
	if _, err := w.Write([]byte("live     5 ho")); err != nil {
		t.Fatal(err)
	}
	if b.Len() != 0 {
		t.Fatal("a partial line was emitted")
	}
	if _, err := w.Write([]byte("sts responded\ngated   12 in scope, probing 9\n")); err != nil {
		t.Fatal(err)
	}
	hist := b.History()
	if len(hist) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(hist), hist)
	}
	if hist[0].Kind != KindCounts || hist[0].Counts["live"] != 5 || hist[0].Phase != "discover" {
		t.Fatalf("first event = %+v", hist[0])
	}
	if hist[1].Counts["gated"] != 12 || hist[1].Counts["probing"] != 9 {
		t.Fatalf("second event = %+v", hist[1])
	}
	w.Flush()
	if b.Len() != 2 {
		t.Fatal("Flush emitted an empty line")
	}
}

func TestWriterFlushEmitsTrailingLine(t *testing.T) {
	b := NewBus(4)
	w := NewWriter(b)
	w.Write([]byte("nuclei  skipped (not installed)")) //nolint:errcheck
	if b.Len() != 0 {
		t.Fatal("emitted before Flush")
	}
	w.Flush()
	hist := b.History()
	if len(hist) != 1 || hist[0].Kind != KindLog || !strings.Contains(hist[0].Text, "skipped") {
		t.Fatalf("history = %+v", hist)
	}
}

func TestWriterSkipsBlankLines(t *testing.T) {
	b := NewBus(4)
	w := NewWriter(b)
	w.Write([]byte("\n\n   \n")) //nolint:errcheck
	w.Flush()
	if b.Len() != 0 {
		t.Fatalf("blank lines were emitted: %+v", b.History())
	}
}
