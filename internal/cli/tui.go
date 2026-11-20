package cli

// The split-pane face of kai.
//
// `kai` with no arguments on a terminal opens four panes over the deterministic
// state every other command already writes: the phases of the workflow on the
// left, the live process stream beside it, the ranked queue and the running job
// below those, and a command line at the bottom.
//
// Nothing here decides anything. The panes render state the kernel produces, and
// every command goes through the same Run() dispatcher the headless CLI uses, so
// scope gates, permissions and output files are identical. When the terminal is
// not a TTY, kai behaves exactly as before: usage text, exit 2.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hourx/kai-harness/pkg/progress"
	"github.com/hourx/kai-harness/pkg/recon"
	"github.com/hourx/kai-harness/pkg/scope"
	"github.com/hourx/kai-harness/pkg/surface"
	"github.com/hourx/kai-harness/pkg/version"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// ---------------------------------------------------------------------------
// Front-end hook used by long phases
// ---------------------------------------------------------------------------

// A phase command reports its progress through two seams the kernel already has:
// recon.Options.Log (human lines) and recon.Options.Confirm (phase boundaries).
// The TUI installs a Bus and a cancellable context for the duration of a run;
// every other caller leaves both nil, which keeps the headless path byte-for-byte
// what it was.
var (
	frontMu  sync.Mutex
	frontBus *progress.Bus
	frontCtx context.Context
)

func setFront(bus *progress.Bus, ctx context.Context) {
	frontMu.Lock()
	frontBus, frontCtx = bus, ctx
	frontMu.Unlock()
}

func frontEnd() (*progress.Bus, context.Context) {
	frontMu.Lock()
	defer frontMu.Unlock()
	return frontBus, frontCtx
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

type tuiStepState string

const (
	stepIdle    tuiStepState = "·"
	stepRunning tuiStepState = "▶"
	stepDone    tuiStepState = "✓"
	stepFailed  tuiStepState = "✗"
)

type tuiStep struct {
	name   string
	state  tuiStepState
	detail string
}

type tuiRunState struct {
	name    string
	phase   string
	started time.Time
}

type tuiResult struct {
	name  string
	code  int
	lines []string
	err   error
}

// tuiApp holds everything one frame needs. Only the event loop mutates it, so no
// locking is needed; background command goroutines talk to it over resCh.
type tuiApp struct {
	raw   *os.File // saved stdout: rendering must survive commands that swap os.Stdout
	bus   *progress.Bus
	sub   <-chan progress.Event
	unsub func()

	plain    bool
	interact bool
	cols     int
	rows     int

	prog     *workspace.Program
	program  string
	platform string
	scopeIn  int
	scopeOut int

	steps  []tuiStep
	lines  []progress.Event
	counts map[string]int
	queue  []surface.Hypothesis

	running *tuiRunState
	resCh   chan tuiResult
	cancel  context.CancelFunc
	notice  string
	input   string
	history []string
	histIdx int
	quit    bool
	dirty   bool
}

var tuiSteps = []string{"discover", "probe", "harvest", "map", "next"}

func defaultSteps() []tuiStep {
	out := make([]tuiStep, 0, len(tuiSteps))
	for _, n := range tuiSteps {
		out = append(out, tuiStep{name: n, state: stepIdle})
	}
	return out
}

// tuiCmd implements `kai tui [program] [--demo] [--frames N]`.
func tuiCmd(args []string) int {
	program, demo, frames := "", false, 4
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--demo":
			demo = true
		case a == "--frames" && i+1 < len(args):
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 1 {
				return fail(fmt.Errorf("--frames wants a positive number"))
			}
			frames = n
		case strings.HasPrefix(a, "-"):
			return fail(fmt.Errorf("usage: kai tui [program] [--demo] [--frames N]"))
		default:
			program = a
		}
	}
	if demo {
		return tuiDemo(frames)
	}
	return tuiInteractive(program)
}

// tuiWanted reports whether `kai` with no arguments should open the workspace.
// Pipes, cron and CI keep the old usage text.
func tuiWanted() bool {
	if os.Getenv("KAI_NO_TUI") != "" {
		return false
	}
	return isTerminal(os.Stdin) && isTerminal(os.Stdout)
}

func tuiInteractive(program string) int {
	app, err := newTUIApp(program)
	if err != nil {
		return fail(err)
	}
	app.interact = true
	return app.loop()
}

func newTUIApp(program string) (*tuiApp, error) {
	p, err := pickProgram(program)
	if err != nil {
		return nil, err
	}
	bus := progress.NewBus(4000)
	sub, unsub := bus.Subscribe()
	cols, rows := termSize(os.Stdout)
	app := &tuiApp{
		raw:      os.Stdout,
		bus:      bus,
		sub:      sub,
		unsub:    unsub,
		cols:     cols,
		rows:     rows,
		prog:     p,
		program:  p.Name,
		platform: p.Meta.Platform,
		steps:    defaultSteps(),
		counts:   map[string]int{},
		resCh:    make(chan tuiResult, 4),
	}
	app.refresh()
	return app, nil
}

// pickProgram opens the named program, or the most recently touched one when the
// operator just types `kai`.
func pickProgram(explicit string) (*workspace.Program, error) {
	if explicit != "" {
		return workspace.Open(explicit)
	}
	names, err := workspace.List()
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no programs yet — run: kai init <name> --platform <p>")
	}
	sort.Slice(names, func(i, j int) bool {
		return dirModTime(names[i]).After(dirModTime(names[j]))
	})
	return workspace.Open(names[0])
}

func dirModTime(name string) time.Time {
	fi, err := os.Stat(workspace.Dir(name))
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// ---------------------------------------------------------------------------
// State loaded from disk
// ---------------------------------------------------------------------------

// refresh re-reads what is on disk. Nothing is remembered between runs: the
// panes only ever show state a command actually wrote.
func (a *tuiApp) refresh() {
	if a.prog == nil {
		return
	}
	a.scopeIn, a.scopeOut = scopeCounts(a.prog)
	if store, err := recon.LoadStore(a.prog.Dir, a.prog.Name); err == nil {
		a.counts["hosts"] = len(store.Hosts)
		a.counts["endpoints"] = len(store.Endpoints)
		a.counts["js"] = len(store.JS)
		live := 0
		for _, h := range store.Hosts {
			if h != nil && h.Status > 0 {
				live++
			}
		}
		if live > 0 {
			a.counts["live_hosts"] = live
		}
	}
	if hasFile(a.prog.Dir, "map.json") {
		a.setStep("map", stepDone, a.stepDetail("map"))
	}
	a.queue = a.loadQueue()
	if len(a.queue) > 0 {
		a.setStep("next", stepDone, fmt.Sprintf("%d hypotheses", len(a.queue)))
	}
}

func (a *tuiApp) stepDetail(name string) string {
	for _, s := range a.steps {
		if s.name == name {
			return s.detail
		}
	}
	return ""
}

// scopeCounts reports how many rules each gate file holds, using the same
// parser the gate itself uses, so the header can never disagree with enforcement.
func scopeCounts(p *workspace.Program) (in, out int) {
	if rules, err := scope.Load(filepath.Join(p.Dir, "scope.txt")); err == nil {
		in = len(rules)
	}
	if rules, err := scope.Load(filepath.Join(p.Dir, "out-of-scope.txt")); err == nil {
		out = len(rules)
	}
	return in, out
}

func hasFile(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

// loadQueue reads the ranked queue written by `kai map`/`kai next`. A missing or
// unreadable file yields no rows; the pane says so instead of inventing entries.
func (a *tuiApp) loadQueue() []surface.Hypothesis {
	if a.prog == nil {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(a.prog.Dir, "next.json"))
	if err != nil {
		return nil
	}
	var plan surface.Plan
	if err := json.Unmarshal(b, &plan); err != nil {
		return nil
	}
	return plan.Items
}

func (a *tuiApp) setStep(name string, state tuiStepState, detail string) {
	for i := range a.steps {
		if a.steps[i].name != name {
			continue
		}
		a.steps[i].state = state
		if detail != "" {
			a.steps[i].detail = detail
		}
		return
	}
}

func (a *tuiApp) markRunningSteps(state tuiStepState) {
	for i := range a.steps {
		if a.steps[i].state == stepRunning {
			a.steps[i].state = state
		}
	}
}

func (a *tuiApp) pushLine(e progress.Event) {
	a.lines = append(a.lines, e)
	if n := len(a.lines); n > 4000 {
		a.lines = append([]progress.Event(nil), a.lines[n-4000:]...)
	}
}

func (a *tuiApp) apply(e progress.Event) {
	switch e.Kind {
	case progress.KindPhase:
		a.setStep(e.Phase, stepRunning, e.Text)
		if a.running != nil {
			a.running.phase = e.Phase
		}
		a.pushLine(e)
		return
	case progress.KindCounts:
		for k, v := range e.Counts {
			a.counts[k] = v
		}
	}
	a.pushLine(e)
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

func (a *tuiApp) loop() int {
	defer a.teardown()
	if !a.plain {
		fmt.Fprint(a.raw, "\033[?1049h\033[?25l\033[2J")
	}
	reader := bufio.NewReader(os.Stdin)
	inCh := make(chan string)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			if line != "" {
				inCh <- strings.TrimRight(line, "\r\n")
			}
			if err != nil {
				close(inCh)
				return
			}
		}
	}()
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	sig := make(chan os.Signal, 4)
	notifySignals(sig)
	defer stopSignals(sig)

	a.render()
	for !a.quit {
		select {
		case e := <-a.sub:
			a.apply(e)
			a.render()
		case res := <-a.resCh:
			a.finish(res)
		case line, ok := <-inCh:
			if !ok {
				a.quit = true
				break
			}
			a.handleInput(line)
		case <-sig:
			if a.running != nil {
				a.abort()
			} else {
				a.quit = true
			}
		case <-tick.C:
			if a.running != nil || a.dirty {
				a.dirty = false
				a.render()
			}
		}
	}
	return 0
}

func (a *tuiApp) teardown() {
	a.unsub()
	if !a.plain {
		fmt.Fprint(a.raw, "\033[?25h\033[?1049l")
	}
}

func (a *tuiApp) finish(res tuiResult) {
	a.running = nil
	if res.code == 0 {
		a.markRunningSteps(stepDone)
		a.notice = res.name + " done"
	} else {
		a.markRunningSteps(stepFailed)
		if res.err != nil {
			a.notice = res.name + ": " + res.err.Error()
		} else {
			a.notice = fmt.Sprintf("%s exit %d", res.name, res.code)
		}
	}
	now := time.Now()
	for _, l := range res.lines {
		a.pushLine(progress.Event{At: now, Kind: progress.KindLog, Text: l})
	}
	a.cancel = nil
	a.refresh()
	a.dirty = true
}

func (a *tuiApp) abort() {
	if a.running == nil {
		return
	}
	if a.cancel != nil {
		a.cancel()
	}
	a.notice = "aborting " + a.running.name
	a.dirty = true
}

func (a *tuiApp) handleInput(raw string) {
	up := strings.Count(raw, "\x1b[A")
	down := strings.Count(raw, "\x1b[B")
	clean := strings.TrimSpace(ansiRE.ReplaceAllString(raw, ""))
	if clean == "" {
		if up > 0 {
			a.historyMove(-up)
		}
		if down > 0 {
			a.historyMove(down)
		}
		a.dirty = true
		return
	}
	if clean != "" {
		a.history = append(a.history, clean)
		a.histIdx = len(a.history)
	}
	a.input = clean
	a.dispatch(clean)
	a.input = ""
	a.dirty = true
}

func (a *tuiApp) historyMove(delta int) {
	if len(a.history) == 0 {
		return
	}
	a.histIdx += delta
	if a.histIdx < 0 {
		a.histIdx = 0
	}
	if a.histIdx > len(a.history) {
		a.histIdx = len(a.history)
	}
	if a.histIdx == len(a.history) {
		a.input = ""
		return
	}
	a.input = a.history[a.histIdx]
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

type tuiCommand struct {
	name  string
	usage string
	help  string
	run   func(a *tuiApp, args []string)
}

// tuiCommands is populated in init so the table can list itself (/help) without a
// package-level initialization cycle.
var tuiCommands []tuiCommand

func init() {
	tuiCommands = []tuiCommand{
		{"help", "/help", "this list", func(a *tuiApp, _ []string) { a.help() }},
		{"enum", "/enum [--rps N]", "run recon: discover → probe → harvest", func(a *tuiApp, args []string) {
			a.runPhase("/enum", append([]string{"recon", a.program}, args...))
		}},
		{"map", "/map", "rebuild map.json/next.json from current state", func(a *tuiApp, _ []string) {
			a.runCapture("/map", []string{"map", a.program})
		}},
		{"next", "/next", "same as /map, then show the queue", func(a *tuiApp, _ []string) {
			a.runCapture("/next", []string{"next", a.program})
		}},
		{"queue", "/queue", "reload the ranked queue from disk", func(a *tuiApp, _ []string) {
			a.queue = a.loadQueue()
			a.notice = fmt.Sprintf("queue: %d hypotheses", len(a.queue))
		}},
		{"plan", "/plan", "queue → waves by precondition", func(a *tuiApp, _ []string) {
			a.runCapture("/plan", []string{"plan", a.program})
		}},
		{"board", "/board", "what is worth doing in every program", func(a *tuiApp, _ []string) {
			a.runCapture("/board", []string{"board", a.program})
		}},
		{"status", "/status", "state on disk for this program", func(a *tuiApp, _ []string) {
			a.runCapture("/status", []string{"status", a.program})
		}},
		{"evidence", "/evidence [list]", "list captured evidence", func(a *tuiApp, args []string) {
			a.runCapture("/evidence", append([]string{"evidence", a.program, "list"}, args...))
		}},
		{"scope", "/scope <host>", "check one host against scope.txt", func(a *tuiApp, args []string) {
			if len(args) == 0 {
				a.notice = "usage: /scope <host>"
				return
			}
			a.runCapture("/scope", append([]string{"scope", a.program}, args...))
		}},
		{"programs", "/programs", "list programs and switch", func(a *tuiApp, args []string) {
			a.programs(args)
		}},
		{"clear", "/clear", "empty the process pane", func(a *tuiApp, _ []string) {
			a.lines = nil
		}},
		{"abort", "/abort", "stop the running command", func(a *tuiApp, _ []string) { a.abort() }},
		{"quit", "/quit", "leave kai (also q)", func(a *tuiApp, _ []string) { a.quit = true }},
		{"probe", "/probe", "phase-level re-run (needs checkpoints — Tier 2)", func(a *tuiApp, _ []string) {
			a.notice = "/probe lands with resumable checkpoints; /enum runs discover→probe→harvest"
		}},
		{"harvest", "/harvest", "phase-level re-run (needs checkpoints — Tier 2)", func(a *tuiApp, _ []string) {
			a.notice = "/harvest lands with resumable checkpoints"
		}},
	}
}

func (a *tuiApp) help() {
	a.pushLine(progress.Event{At: time.Now(), Kind: progress.KindLog, Text: "commands:"})
	for _, c := range tuiCommands {
		a.pushLine(progress.Event{At: time.Now(), Kind: progress.KindLog,
			Text: fmt.Sprintf("  %-26s %s", c.usage, c.help)})
	}
	a.notice = "/help"
}

func (a *tuiApp) dispatch(line string) {
	if line == "q" || line == "exit" || line == "quit" {
		a.quit = true
		return
	}
	if !strings.HasPrefix(line, "/") {
		a.notice = "commands start with / — try /help"
		return
	}
	fields := strings.Fields(line)
	name := strings.TrimPrefix(fields[0], "/")
	for _, c := range tuiCommands {
		if c.name != name {
			continue
		}
		c.run(a, fields[1:])
		return
	}
	a.notice = "unknown command /" + name + " — try /help"
}

func (a *tuiApp) programs(args []string) {
	if len(args) > 0 {
		p, err := workspace.Open(args[0])
		if err != nil {
			a.notice = err.Error()
			return
		}
		a.prog, a.program, a.platform = p, p.Name, p.Meta.Platform
		a.steps = defaultSteps()
		a.counts = map[string]int{}
		a.queue = nil
		a.refresh()
		a.notice = "switched to " + p.Name
		return
	}
	names, err := workspace.List()
	if err != nil {
		a.notice = err.Error()
		return
	}
	now := time.Now()
	for _, n := range names {
		mark := " "
		if n == a.program {
			mark = "*"
		}
		a.pushLine(progress.Event{At: now, Kind: progress.KindLog, Text: fmt.Sprintf("%s %s", mark, n)})
	}
	a.notice = fmt.Sprintf("%d programs — /programs <name> to switch", len(names))
}

// runPhase runs a command whose kernel writes structured progress, streaming it
// into the panes. stdout goes to /dev/null because the same lines already arrive
// through the Bus; letting them through would both tear the frame and double
// every line.
func (a *tuiApp) runPhase(name string, args []string) {
	if a.running != nil {
		a.notice = "busy: " + a.running.name
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.running = &tuiRunState{name: name, started: time.Now()}
	for _, s := range tuiSteps[:3] {
		a.setStep(s, stepIdle, "")
	}
	a.pushLine(progress.Event{At: time.Now(), Kind: progress.KindLog, Text: strings.Join(args, " ")})
	go func() {
		oldOut, oldErr := os.Stdout, os.Stderr
		devnull, derr := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if derr == nil {
			os.Stdout, os.Stderr = devnull, devnull
		}
		setFront(a.bus, ctx)
		code := Run(args)
		setFront(nil, nil)
		if derr == nil {
			devnull.Close()
		}
		os.Stdout, os.Stderr = oldOut, oldErr
		a.resCh <- tuiResult{name: name, code: code}
	}()
}

// runCapture runs a command that only prints a report. Its stdout/stderr are
// piped straight into the process pane.
func (a *tuiApp) runCapture(name string, args []string) {
	if a.running != nil {
		a.notice = "busy: " + a.running.name
		return
	}
	a.running = &tuiRunState{name: name, started: time.Now()}
	go func() {
		oldOut, oldErr := os.Stdout, os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			a.resCh <- tuiResult{name: name, code: 2, err: err}
			return
		}
		os.Stdout, os.Stderr = w, w
		done := make(chan int, 1)
		go func() {
			code := Run(args)
			// Close the write end before reporting: the reader below ends on EOF,
			// and it is the only writer left once the command has returned.
			w.Close()
			done <- code
		}()
		var lines []string
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		code := <-done
		r.Close()
		os.Stdout, os.Stderr = oldOut, oldErr
		a.resCh <- tuiResult{name: name, code: code, lines: lines}
	}()
}

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

func (a *tuiApp) render() {
	f := a.frame()
	if a.plain {
		fmt.Fprint(a.raw, f.String()+"\n")
		return
	}
	io.WriteString(a.raw, f.Render()) //nolint:errcheck
	if a.interact {
		fmt.Fprintf(a.raw, "\033[%d;3H", a.rows)
	}
}

func (a *tuiApp) frame() *canvas {
	// Sizes are taken as given: a frame is always exactly the terminal's size, so
	// it can never scroll the screen. Everything below degrades by dropping panes,
	// not by drawing outside the grid.
	cols, rows := a.cols, a.rows
	if cols < 1 {
		cols = 1
	}
	if rows < 1 {
		rows = 1
	}
	c := newCanvas(cols, rows)

	inRow := rows - 1
	bodyH := inRow - 1
	if bodyH < 1 {
		bodyH = 1
	}
	compact := cols < 84 || rows < 20
	qH := 0
	if !compact && bodyH >= 12 {
		qH = 7
	}
	topH := bodyH - qH
	if topH < 3 {
		topH, qH = bodyH, 0
	}
	stepsW := cols / 4
	if stepsW < 20 {
		stepsW = 20
	}
	if stepsW > 30 {
		stepsW = 30
	}
	if stepsW > cols-20 {
		stepsW = cols - 20
	}
	if stepsW < 4 {
		stepsW = 4
	}
	procW := cols - stepsW
	if procW < 4 {
		procW = 4
		stepsW = cols - procW
		if stepsW < 1 {
			stepsW = 1
		}
	}

	// Header bar.
	c.hline(0, 0, cols, '─')
	c.put(1, 0, " kai ")
	c.put(7, 0, fmt.Sprintf(" %s · %s · scope %d in / %d out ", a.program, a.platformLabel(), a.scopeIn, a.scopeOut))
	right := a.notice
	if right == "" {
		right = version.String()
	}
	c.put(cols-len(right)-2, 0, " "+right+" ")

	// STEPS / PROCESS.
	c.box(0, 1, stepsW, topH, " STEPS ")
	for i, s := range a.steps {
		y := 2 + i
		if y >= 1+topH-1 {
			break
		}
		line := fmt.Sprintf("%s %-9s %s", string(s.state), s.name, s.detail)
		c.put(2, y, fit(line, stepsW-4))
	}
	c.box(stepsW, 1, procW, topH, " PROCESS ")
	inner := procW - 4
	// Feed the lines above a separator, then the counters on the last inner row.
	feed := topH - 4
	for i, e := range tail(a.lines, feed) {
		c.put(stepsW+2, 2+i, fit(a.fmtEvent(e), inner))
	}
	if topH >= 5 {
		c.hline(stepsW+1, topH-2, procW-2, '─')
		c.put(stepsW+2, topH-1, fit(a.countsLine(), inner))
	}

	// QUEUE / RUNNING.
	if qH > 0 {
		qW := cols - 32
		if qW < 24 {
			qW = cols
		}
		c.box(0, 1+topH, qW, qH, " QUEUE ")
		if len(a.queue) == 0 {
			c.put(2, 2+topH, fit("no queue yet — run /enum then /map", qW-4))
		}
		for i, h := range a.queue {
			y := 2 + topH + i
			if y >= 1+topH+qH-1 {
				break
			}
			line := fmt.Sprintf("%d %s  %s", i+1, h.Target, h.Class)
			c.put(2, y, fit(line, qW-4))
		}
		if qW < cols {
			c.box(qW, 1+topH, cols-qW, qH, " RUNNING ")
			c.put(qW+2, 2+topH, fit(a.runningLine(), cols-qW-4))
			c.put(qW+2, 3+topH, fit(a.runningState(), cols-qW-4))
		}
	}

	// Input line.
	c.put(0, inRow, fit("> "+a.input, cols-30))
	hint := "/help · ctrl-c=abort"
	c.put(cols-len(hint)-1, inRow, hint)
	return c
}

func (a *tuiApp) platformLabel() string {
	if a.platform == "" {
		return "no platform"
	}
	return a.platform
}

func (a *tuiApp) fmtEvent(e progress.Event) string {
	stamp := ""
	if !e.At.IsZero() {
		stamp = e.At.Format("15:04:05") + " "
	}
	phase := ""
	if e.Phase != "" {
		phase = fmt.Sprintf("%-8s ", e.Phase)
	}
	return trim(stamp + phase + e.Text)
}

// countsLine only prints counters that exist. A number nobody measured is never
// shown.
func (a *tuiApp) countsLine() string {
	order := []string{"discovered", "gated", "probing", "resolved", "resolved_of", "live", "urls", "bundles", "endpoints", "hosts", "js"}
	var parts []string
	for _, k := range order {
		v, ok := a.counts[k]
		if !ok {
			continue
		}
		label := k
		if k == "resolved_of" {
			continue // folded into "resolved N/M" above
		}
		if k == "resolved" {
			if of, ok := a.counts["resolved_of"]; ok {
				parts = append(parts, fmt.Sprintf("%s %d/%d", label, v, of))
				continue
			}
		}
		parts = append(parts, fmt.Sprintf("%s %d", label, v))
	}
	if len(parts) == 0 {
		return "counters: none yet"
	}
	return strings.Join(parts, "  ")
}

func (a *tuiApp) runningLine() string {
	if a.running == nil {
		return "idle"
	}
	return a.running.name
}

func (a *tuiApp) runningState() string {
	if a.running == nil {
		return "type /enum to start"
	}
	el := time.Since(a.running.started).Round(time.Second)
	phase := a.running.phase
	if phase == "" {
		phase = "starting"
	}
	return fmt.Sprintf("%s  %s", phase, el)
}

// tail returns the last n events, oldest first.
func tail(evs []progress.Event, n int) []progress.Event {
	if n <= 0 {
		return nil
	}
	if len(evs) <= n {
		return evs
	}
	return evs[len(evs)-n:]
}

// ---------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------

// termSize reports the terminal size, falling back to a sane default when the
// size cannot be read (pipes, unusual terminals). KAI_TUI_SIZE=COLSxROWS
// overrides it, which is what the tests and the demo renderer use.
func termSize(f *os.File) (cols, rows int) {
	if v := os.Getenv("KAI_TUI_SIZE"); v != "" {
		if c, r, ok := parseSize(v); ok {
			return c, r
		}
	}
	if f != nil {
		cmd := exec.Command("stty", "size")
		cmd.Stdin = f
		if out, err := cmd.Output(); err == nil {
			var r, c int
			if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d %d", &r, &c); err == nil && c > 0 && r > 0 {
				return c, r
			}
		}
	}
	return 100, 30
}

func parseSize(v string) (int, int, bool) {
	parts := strings.SplitN(strings.ToLower(v), "x", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	c, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	r, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || c < 10 || r < 5 {
		return 0, 0, false
	}
	return c, r, true
}

// notifySignals subscribes to the signals the workspace reacts to: ctrl-c aborts
// a running command instead of killing the process.
func notifySignals(ch chan os.Signal) {
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
}

func stopSignals(ch chan os.Signal) { signal.Stop(ch) }

// ---------------------------------------------------------------------------
// Demo renderer
// ---------------------------------------------------------------------------

// tuiDemo renders scripted frames with no terminal and no network, so the layout
// can be reviewed over a pipe (and by tests). It is labelled demo inside the
// frame: the numbers are a sample, not a run.
func tuiDemo(frames int) int {
	app := &tuiApp{
		raw:      os.Stdout,
		plain:    true,
		program:  "demo",
		platform: "hackerone",
		scopeIn:  12,
		scopeOut: 3,
		steps:    defaultSteps(),
		counts:   map[string]int{},
		cols:     104,
		rows:     24,
	}
	if c, r, ok := parseSize(os.Getenv("KAI_TUI_SIZE")); ok {
		app.cols, app.rows = c, r
	}
	at := time.Date(2026, 11, 20, 11, 4, 2, 0, time.UTC)
	step := func(s int) time.Time { return at.Add(time.Duration(s) * time.Second) }
	type frameScript struct {
		events []progress.Event
		stages func(a *tuiApp)
	}
	scripts := []frameScript{
		{stages: func(a *tuiApp) {
			a.setStep("discover", stepRunning, "subdomains for demo.example")
			a.running = &tuiRunState{name: "/enum", started: time.Now()}
		}},
		{events: []progress.Event{
			{At: step(0), Kind: progress.KindPhase, Phase: "discover", Text: "subdomain enumeration for demo.example"},
			{At: step(1), Kind: progress.KindCounts, Phase: "discover", Text: "subfinder   214 hosts  (/usr/bin/subfinder)", Counts: map[string]int{"discovered": 214}},
			{At: step(3), Kind: progress.KindCounts, Phase: "discover", Text: "gated   12 in scope, probing 9", Counts: map[string]int{"gated": 12, "probing": 9}},
		}},
		{events: []progress.Event{
			{At: step(4), Kind: progress.KindPhase, Phase: "probe", Text: "resolve and HTTP-probe 9 in-scope hosts"},
			{At: step(7), Kind: progress.KindCounts, Phase: "probe", Text: "resolved 7/9", Counts: map[string]int{"resolved": 7, "resolved_of": 9}},
			{At: step(9), Kind: progress.KindCounts, Phase: "probe", Text: "live     5 hosts responded", Counts: map[string]int{"live": 5}},
		}},
		{events: []progress.Event{
			{At: step(12), Kind: progress.KindPhase, Phase: "harvest", Text: "collect historical URLs, JavaScript bundles and endpoints"},
			{At: step(19), Kind: progress.KindCounts, Phase: "harvest", Text: "urls   214 in-scope, bundles 31 (public JS, no session on external hosts)", Counts: map[string]int{"urls": 214, "bundles": 31}},
			{At: step(20), Kind: progress.KindLog, Phase: "harvest", Text: "endpoints 486"},
			{At: step(21), Kind: progress.KindDone, Phase: "harvest", Text: "done in 21s"},
		}},
	}
	if frames > len(scripts) {
		frames = len(scripts)
	}
	for i := 0; i < frames; i++ {
		s := scripts[i]
		if s.stages != nil {
			s.stages(app)
		}
		for _, e := range s.events {
			if e.Kind == progress.KindPhase {
				app.setStep(e.Phase, stepRunning, e.Text)
				if app.running != nil {
					app.running.phase = e.Phase
				}
			}
			if e.Kind == progress.KindCounts {
				for k, v := range e.Counts {
					app.counts[k] = v
				}
			}
			app.pushLine(e)
		}
		if i == len(scripts)-1 {
			app.running = nil
			app.markRunningSteps(stepDone)
			app.counts["endpoints"] = 486
			app.counts["hosts"] = 5
			app.queue = demoQueue()
			app.setStep("map", stepDone, "486 endpoints")
			app.setStep("next", stepDone, "5 hypotheses")
			app.notice = "demo frame — numbers are a sample, not a run"
		}
		fmt.Printf("── frame %d/%d ──\n", i+1, frames)
		fmt.Println(app.frame().String())
	}
	return 0
}

func demoQueue() []surface.Hypothesis {
	return []surface.Hypothesis{
		{Target: "api.example.com/u/1/profile", Class: "IDOR/BOLA"},
		{Target: "example.com/redirect?to=", Class: "open-redirect"},
		{Target: "app.example.com/graphql", Class: "graphql"},
		{Target: "cdn.example.com/up", Class: "file-upload/SSRF"},
		{Target: "example.com/api/v2/coupon", Class: "business-logic"},
	}
}
