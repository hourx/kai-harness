// Package progress carries structured progress events from a long-running
// kernel phase to whatever is drawing them: the plain CLI, the split-pane TUI,
// or a test harness.
//
// The kernel knows about none of them. It keeps writing human-readable lines to
// its Log writer and calling its Confirm hook before each phase. A Writer adapts
// those lines into Events; a Bus fans the Events out to subscribers while
// keeping a bounded history so a renderer that attaches late can still draw the
// backlog.
//
// Nothing here changes what a run does. Progress is a view over the pipeline,
// never a participant in it: a subscriber that falls behind drops events
// instead of stalling the phase that produced them.
package progress

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kind classifies an Event.
type Kind string

const (
	// KindPhase marks a phase boundary: the kernel is about to start Phase.
	KindPhase Kind = "phase"
	// KindLog is one line of kernel output that carried no counter.
	KindLog Kind = "log"
	// KindCounts is a counter update parsed out of a kernel line.
	KindCounts Kind = "counts"
	// KindDone reports a finished phase together with its summary.
	KindDone Kind = "done"
	// KindError reports a phase that ended with an error.
	KindError Kind = "error"
)

// Event is one thing that happened during a run.
type Event struct {
	At     time.Time
	Kind   Kind
	Phase  string
	Text   string
	Counts map[string]int
}

// Bus fans Events out to subscribers and keeps a bounded history. Safe for
// concurrent use.
type Bus struct {
	mu     sync.Mutex
	subs   map[int]chan Event
	nextID int
	hist   []Event
	limit  int
}

// NewBus returns a Bus that retains at most history Events. A history below 1
// is raised to 1 so a late subscriber always gets the most recent event.
func NewBus(history int) *Bus {
	if history < 1 {
		history = 1
	}
	return &Bus{subs: map[int]chan Event{}, limit: history}
}

// Emit records an Event and hands it to every subscriber. A subscriber that is
// not keeping up loses events rather than blocking the run.
func (b *Bus) Emit(e Event) {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hist = append(b.hist, e)
	if len(b.hist) > b.limit {
		b.hist = append([]Event(nil), b.hist[len(b.hist)-b.limit:]...)
	}
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Subscribe returns a channel of future Events plus the function that cancels
// the subscription. The channel is buffered and is never closed by the Bus, so
// a reader that stops drains and discards rather than panicking.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 512)
	b.mu.Lock()
	id := b.nextID
	b.nextID++
	b.subs[id] = ch
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, id)
		b.mu.Unlock()
	}
}

// History returns a copy of the retained Events, oldest first.
func (b *Bus) History() []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Event(nil), b.hist...)
}

// Len reports how many Events are retained.
func (b *Bus) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.hist)
}

// Writer adapts the kernel's Log writer into Events. The kernel writes one
// human line per progress step; the Writer splits on newlines, keeps the partial
// tail, parses whatever counters it recognises and emits one Event per complete
// line.
type Writer struct {
	bus   *Bus
	mu    sync.Mutex
	phase string
	buf   []byte
}

// NewWriter returns a Writer that emits into bus.
func NewWriter(bus *Bus) *Writer { return &Writer{bus: bus} }

// SetPhase labels subsequent lines with the phase that produced them.
func (w *Writer) SetPhase(phase string) {
	w.mu.Lock()
	w.phase = phase
	w.mu.Unlock()
}

// Write implements io.Writer. It always reports the full length: a front-end
// that fails to record progress must not fail the run.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.buf = append(w.buf, p...)
	var lines []string
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		lines = append(lines, string(w.buf[:i]))
		w.buf = append([]byte(nil), w.buf[i+1:]...)
	}
	phase := w.phase
	w.mu.Unlock()
	for _, line := range lines {
		w.emit(phase, line)
	}
	return len(p), nil
}

// Flush emits any partial trailing line. Callers that own a run call it once the
// run returns.
func (w *Writer) Flush() {
	w.mu.Lock()
	rest := string(w.buf)
	w.buf = nil
	phase := w.phase
	w.mu.Unlock()
	if strings.TrimSpace(rest) != "" {
		w.emit(phase, rest)
	}
}

func (w *Writer) emit(phase, line string) {
	line = strings.TrimRight(line, " \t\r")
	if strings.TrimSpace(line) == "" {
		return
	}
	e := Event{Kind: KindLog, Phase: phase, Text: line}
	if counts := ParseCounts(line); len(counts) > 0 {
		e.Kind = KindCounts
		e.Counts = counts
	}
	w.bus.Emit(e)
}

// ParseCounts reads the counters out of a kernel progress line. It understands
// only the lines the kernel actually prints; anything else returns nil, so a
// kernel message change degrades to "no counters", never to a wrong number.
//
// Recognised today (pkg/recon):
//
//	  subfinder        214 hosts   (/usr/bin/subfinder)
//	gated   12 in scope, probing 9
//	resolved 7/9
//	live     5 hosts responded
//	urls   214 in-scope, bundles 31 (public JS, no session on external hosts)
func ParseCounts(line string) map[string]int {
	f := strings.Fields(line)
	if len(f) == 0 {
		return nil
	}
	switch f[0] {
	case "gated":
		// gated N in scope, probing M
		if len(f) >= 6 && f[2] == "in" && f[3] == "scope," && f[4] == "probing" {
			out := map[string]int{}
			if n, err := strconv.Atoi(f[1]); err == nil {
				out["gated"] = n
			}
			if n, err := strconv.Atoi(f[5]); err == nil {
				out["probing"] = n
			}
			return nonEmpty(out)
		}
	case "resolved":
		if len(f) >= 2 {
			if n, total, ok := splitPair(f[1]); ok {
				return map[string]int{"resolved": n, "resolved_of": total}
			}
		}
	case "live":
		// live N hosts responded
		if len(f) >= 3 && f[2] == "hosts" {
			if n, err := strconv.Atoi(f[1]); err == nil {
				return map[string]int{"live": n}
			}
		}
	case "urls":
		// urls N in-scope, bundles M (...)
		if len(f) >= 5 && f[2] == "in-scope," && f[3] == "bundles" {
			out := map[string]int{}
			if n, err := strconv.Atoi(f[1]); err == nil {
				out["urls"] = n
			}
			if n, err := strconv.Atoi(strings.TrimRight(f[4], ",")); err == nil {
				out["bundles"] = n
			}
			return nonEmpty(out)
		}
	default:
		// adapter line: "<name> <N> hosts (<path>)"
		if len(f) >= 3 && f[2] == "hosts" {
			if n, err := strconv.Atoi(f[1]); err == nil {
				return map[string]int{"discovered": n}
			}
		}
	}
	return nil
}

func nonEmpty(m map[string]int) map[string]int {
	if len(m) == 0 {
		return nil
	}
	return m
}

// splitPair parses "7/9".
func splitPair(s string) (int, int, bool) {
	i := strings.IndexByte(s, '/')
	if i <= 0 || i == len(s)-1 {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(s[:i])
	b, err2 := strconv.Atoi(s[i+1:])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return a, b, true
}
