package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hourx/kai-harness/pkg/progress"
	"github.com/hourx/kai-harness/pkg/surface"
	"github.com/hourx/kai-harness/pkg/workspace"
)

func testApp(cols, rows int) *tuiApp {
	a := &tuiApp{
		cols:     cols,
		rows:     rows,
		program:  "demo",
		platform: "hackerone",
		steps:    defaultSteps(),
		counts:   map[string]int{},
		notice:   "ready",
	}
	a.setStep("discover", stepDone, "214 hosts")
	a.pushLine(progress.Event{At: time.Date(2026, 11, 20, 11, 4, 2, 0, time.UTC), Kind: progress.KindLog, Text: "live     5 hosts responded"})
	a.queue = []surface.Hypothesis{{Target: "api.demo.example/u/1", Class: "IDOR/BOLA"}}
	return a
}

// A frame must always be exactly rows tall and never wider than the terminal.
func TestFrameFitsTerminal(t *testing.T) {
	for _, size := range [][2]int{{104, 24}, {100, 30}, {60, 14}, {40, 10}, {30, 8}, {200, 60}} {
		a := testApp(size[0], size[1])
		lines := strings.Split(a.frame().String(), "\n")
		if len(lines) != size[1] {
			t.Fatalf("%v: got %d rows, want %d", size, len(lines), size[1])
		}
		for i, l := range lines {
			if n := len([]rune(l)); n > size[0] {
				t.Fatalf("%v: row %d is %d wide: %q", size, i, n, l)
			}
			if strings.Contains(l, "\t") {
				t.Fatalf("%v: row %d contains a tab: %q", size, i, l)
			}
		}
	}
}

func TestFrameShowsAllPanesWhenRoomy(t *testing.T) {
	f := testApp(104, 26).frame().String()
	for _, want := range []string{" kai ", "STEPS", "PROCESS", "QUEUE", "RUNNING", "discover", "api.demo.example/u/1", "> ", "/help"} {
		if !strings.Contains(f, want) {
			t.Fatalf("frame is missing %q:\n%s", want, f)
		}
	}
}

// A short or narrow terminal drops the lower panes instead of drawing over them.
func TestFrameDropsQueuePanesWhenCompact(t *testing.T) {
	f := testApp(70, 16).frame().String()
	if strings.Contains(f, "QUEUE") || strings.Contains(f, "RUNNING") {
		t.Fatalf("compact frame kept the lower panes:\n%s", f)
	}
	for _, want := range []string{"STEPS", "PROCESS"} {
		if !strings.Contains(f, want) {
			t.Fatalf("compact frame is missing %q:\n%s", want, f)
		}
	}
}

func TestFrameStepsTrackState(t *testing.T) {
	a := testApp(104, 26)
	a.setStep("probe", stepRunning, "resolving")
	f := a.frame().String()
	if !strings.Contains(f, "▶ probe") {
		t.Fatalf("running step not marked:\n%s", f)
	}
	if !strings.Contains(f, "✓ discover") {
		t.Fatalf("done step not marked:\n%s", f)
	}
	if !strings.Contains(f, "· harvest") {
		t.Fatalf("idle step not marked:\n%s", f)
	}
}

// Counters show only what was measured. Nothing is ever invented.
func TestCountsLineOnlyShowsMeasuredValues(t *testing.T) {
	a := testApp(104, 26)
	a.counts = map[string]int{}
	if got := a.countsLine(); got != "counters: none yet" {
		t.Fatalf("empty counts = %q", got)
	}
	a.counts = map[string]int{"resolved": 7, "resolved_of": 9, "live": 5}
	got := a.countsLine()
	for _, want := range []string{"resolved 7/9", "live 5"} {
		if !strings.Contains(got, want) {
			t.Fatalf("counts = %q, want %q", got, want)
		}
	}
	for _, banned := range []string{"pid", "reqs", "requests"} {
		if strings.Contains(got, banned) {
			t.Fatalf("counts line invented %q: %q", banned, got)
		}
	}
}

func TestRunningStateWithoutRun(t *testing.T) {
	a := testApp(104, 26)
	if a.runningLine() != "idle" {
		t.Fatalf("runningLine = %q", a.runningLine())
	}
	if !strings.Contains(a.runningState(), "/enum") {
		t.Fatalf("idle hint = %q", a.runningState())
	}
	a.running = &tuiRunState{name: "/enum", phase: "probe", started: time.Now().Add(-3 * time.Second)}
	if a.runningLine() != "/enum" {
		t.Fatalf("runningLine = %q", a.runningLine())
	}
	if !strings.Contains(a.runningState(), "probe") {
		t.Fatalf("runningState = %q", a.runningState())
	}
}

func TestCommandTableIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range tuiCommands {
		if c.name == "" || c.run == nil || c.help == "" {
			t.Fatalf("incomplete command: %+v", c)
		}
		if !strings.HasPrefix(c.usage, "/"+c.name) {
			t.Fatalf("usage %q does not start with /%s", c.usage, c.name)
		}
		if seen[c.name] {
			t.Fatalf("duplicate command %q", c.name)
		}
		seen[c.name] = true
	}
	for _, want := range []string{"help", "enum", "map", "next", "queue", "plan", "board", "status", "evidence", "scope", "programs", "clear", "abort", "quit"} {
		if !seen[want] {
			t.Fatalf("command %q is missing from the table", want)
		}
	}
}

func TestDispatchRoutesAndReports(t *testing.T) {
	a := testApp(104, 26)
	a.dispatch("/help")
	if a.notice != "/help" {
		t.Fatalf("notice = %q", a.notice)
	}
	joined := a.frame().String()
	if !strings.Contains(joined, "/enum") {
		t.Fatalf("/help did not list the command table:\n%s", joined)
	}

	a.dispatch("/nope")
	if !strings.Contains(a.notice, "unknown command") {
		t.Fatalf("notice = %q", a.notice)
	}

	a.notice = ""
	a.dispatch("enum") // no slash
	if !strings.Contains(a.notice, "/help") {
		t.Fatalf("bare text notice = %q", a.notice)
	}
}

func TestDispatchQuit(t *testing.T) {
	for _, line := range []string{"/quit", "q", "quit", "exit"} {
		a := testApp(104, 26)
		a.dispatch(line)
		if !a.quit {
			t.Fatalf("%q did not quit", line)
		}
	}
}

func TestDispatchScopeNeedsHost(t *testing.T) {
	a := testApp(104, 26)
	a.dispatch("/scope")
	if !strings.Contains(a.notice, "usage: /scope") {
		t.Fatalf("notice = %q", a.notice)
	}
}

func TestDispatchClearEmptiesProcessPane(t *testing.T) {
	a := testApp(104, 26)
	a.dispatch("/clear")
	if len(a.lines) != 0 {
		t.Fatalf("lines = %d", len(a.lines))
	}
}

// A second command must not start while one is running.
func TestBusyGuard(t *testing.T) {
	a := testApp(104, 26)
	a.running = &tuiRunState{name: "/enum", started: time.Now()}
	a.dispatch("/map")
	if !strings.HasPrefix(a.notice, "busy: ") {
		t.Fatalf("notice = %q", a.notice)
	}
	if a.running.name != "/enum" {
		t.Fatalf("running changed to %q", a.running.name)
	}
}

func TestInputTrimsAndRemembersHistory(t *testing.T) {
	a := testApp(104, 26)
	a.handleInput("   /clear  ")
	if len(a.history) != 1 || a.history[0] != "/clear" {
		t.Fatalf("history = %v", a.history)
	}
	if a.input != "" {
		t.Fatalf("input was not reset: %q", a.input)
	}
	a.handleInput("\x1b[A") // arrow up: recall
	if a.input != "/clear" {
		t.Fatalf("recall = %q", a.input)
	}
	a.handleInput("\x1b[B") // arrow down: back to a blank line
	if a.input != "" {
		t.Fatalf("history forward = %q", a.input)
	}
}

func TestInputIgnoresEscapeNoise(t *testing.T) {
	a := testApp(104, 26)
	a.handleInput("\x1b[1;5C/clear\x1b[0m")
	if len(a.lines) != 0 {
		t.Fatalf("/clear driven by noisy input left %d lines", len(a.lines))
	}
	if len(a.history) != 1 || a.history[0] != "/clear" {
		t.Fatalf("history = %v", a.history)
	}
}

func TestRefreshWithoutProgramIsSafe(t *testing.T) {
	a := testApp(104, 26)
	a.prog = nil
	a.refresh() // must not panic
}

func TestScopeCountsUsesGateParser(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("scope.txt", "# comment\n\n*.demo.example\napi.demo.example\n")
	write("out-of-scope.txt", "cdn.demo.example\n")
	p := &workspace.Program{Dir: dir, Name: "demo"}
	in, out := scopeCounts(p)
	if in != 2 || out != 1 {
		t.Fatalf("scopeCounts = %d in / %d out, want 2 in / 1 out", in, out)
	}
}

func TestParseSize(t *testing.T) {
	if c, r, ok := parseSize("120x40"); !ok || c != 120 || r != 40 {
		t.Fatalf("parseSize = %d,%d,%v", c, r, ok)
	}
	if _, _, ok := parseSize("nonsense"); ok {
		t.Fatal("nonsense parsed")
	}
	if _, _, ok := parseSize("5x3"); ok {
		t.Fatal("a terminal too small to draw parsed")
	}
}

func TestTail(t *testing.T) {
	evs := []progress.Event{{Text: "a"}, {Text: "b"}, {Text: "c"}}
	if got := tail(evs, 2); len(got) != 2 || got[0].Text != "b" {
		t.Fatalf("tail = %+v", got)
	}
	if got := tail(evs, 0); got != nil {
		t.Fatalf("tail(0) = %+v", got)
	}
	if got := tail(nil, 3); len(got) != 0 {
		t.Fatalf("tail(nil) = %+v", got)
	}
}

// The process pane keeps the most recent lines, and the buffer stays bounded
// even during a run that prints tens of thousands of lines.
func TestPushLineIsBounded(t *testing.T) {
	a := testApp(104, 26)
	for i := 0; i < 9000; i++ {
		a.pushLine(progress.Event{Kind: progress.KindLog, Text: "line"})
	}
	if len(a.lines) > 4000 {
		t.Fatalf("lines = %d", len(a.lines))
	}
}

// Schedule emits must feed the panes exactly like a live run does.
func TestApplyRoutesPhaseAndCounts(t *testing.T) {
	a := testApp(104, 26)
	a.running = &tuiRunState{name: "/enum", started: time.Now()}
	a.apply(progress.Event{Kind: progress.KindPhase, Phase: "probe", Text: "resolve 9 hosts"})
	if a.running.phase != "probe" {
		t.Fatalf("phase = %q", a.running.phase)
	}
	if a.stepDetail("probe") != "resolve 9 hosts" {
		t.Fatalf("step detail = %q", a.stepDetail("probe"))
	}
	a.apply(progress.Event{Kind: progress.KindCounts, Counts: map[string]int{"live": 5}})
	if a.counts["live"] != 5 {
		t.Fatalf("counts = %v", a.counts)
	}
}

func TestMarkRunningSteps(t *testing.T) {
	a := testApp(104, 26)
	a.setStep("probe", stepRunning, "")
	a.setStep("harvest", stepRunning, "")
	a.markRunningSteps(stepFailed)
	if a.steps[1].state != stepFailed || a.steps[2].state != stepFailed {
		t.Fatalf("steps = %+v", a.steps)
	}
	if a.steps[0].state != stepDone {
		t.Fatalf("a finished step was overwritten: %+v", a.steps[0])
	}
}

// A captured command must report back. The reader ends on EOF, so the writer has
// to be closed when the command returns; without that the pane hangs on "starting"
// forever while the command itself took milliseconds.
func TestRunCaptureReportsBack(t *testing.T) {
	a := testApp(104, 26)
	a.resCh = make(chan tuiResult, 4)
	a.runCapture("/version", []string{"version"})
	select {
	case res := <-a.resCh:
		if res.code != 0 {
			t.Fatalf("code = %d, lines = %v", res.code, res.lines)
		}
		if len(res.lines) == 0 || !strings.Contains(res.lines[0], "kai ") {
			t.Fatalf("captured lines = %v", res.lines)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("captured command never returned")
	}
}

// A streaming phase reports back the same way, with its output suppressed.
func TestRunPhaseReportsBack(t *testing.T) {
	a := testApp(104, 26)
	a.resCh = make(chan tuiResult, 4)
	a.runPhase("/version", []string{"version"})
	if a.running == nil {
		t.Fatal("no run recorded")
	}
	select {
	case res := <-a.resCh:
		if res.code != 0 {
			t.Fatalf("code = %d", res.code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("phase never returned")
	}
}

// Cancel must be wired up while a phase runs and released afterwards.
func TestRunPhaseCancelWiring(t *testing.T) {
	a := testApp(104, 26)
	a.resCh = make(chan tuiResult, 4)
	a.runPhase("/version", []string{"version"})
	if a.cancel == nil {
		t.Fatal("no cancel function recorded")
	}
	<-a.resCh
	a.running = nil
	a.notice = ""
	a.abort() // must be a no-op once nothing runs
	if a.notice != "" {
		t.Fatalf("abort with no run set a notice: %q", a.notice)
	}
}
