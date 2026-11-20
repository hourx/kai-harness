package serve

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hourx/kai-harness/pkg/progress"
)

// ProgressFile is the per-run event log `kai recon` writes inside a program's
// state directory. The watcher only ever reads it.
const ProgressFile = "state/progress.jsonl"

const (
	watchPoll      = 250 * time.Millisecond
	watchKeepalive = 15 * time.Second
	watchMaxOpen   = 8
)

// watchers counts live SSE connections, so a published port cannot be turned
// into a file-descriptor sink by opening watch routes in a loop.
var watchers int64

// watch streams a program's run events as Server-Sent Events.
//
// It is a tail on a file, nothing more: the handler never runs a command and
// never writes. `?backlog=0` skips the events already recorded and streams only
// what happens next; the default replays the file first so a watcher that
// connects mid-run is not blind to the run so far.
func (s *Server) watch(w http.ResponseWriter, r *http.Request, dir string) {
	if n := atomic.AddInt64(&watchers, 1); n > watchMaxOpen {
		atomic.AddInt64(&watchers, -1)
		s.writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many watchers"})
		return
	}
	defer atomic.AddInt64(&watchers, -1)

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.fail(w, http.StatusInternalServerError, errors.New("streaming is not supported by this server"))
		return
	}
	// The server arms a write deadline on every request; a stream has to outlive
	// it. Left alone, WriteTimeout severs a watcher mid-run while it is still
	// calmly reading — the connection just ends. Clear the deadline for this
	// response only, so every other route keeps its 60s guard.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	path := filepath.Join(dir, ProgressFile)
	backlog := true
	if v := strings.TrimSpace(r.URL.Query().Get("backlog")); v == "0" || strings.EqualFold(v, "false") {
		backlog = false
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, ": kai watch %s\n", ProgressFile)
	flusher.Flush()

	ctx := r.Context()
	var offset int64
	if backlog {
		// Replay what is already recorded. A missing file is not an error: the
		// run may not have started yet, and the stream simply waits for it.
		if f, err := os.Open(path); err == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				line := sc.Bytes()
				if !writeFrame(w, line) {
					f.Close()
					return
				}
				offset += int64(len(line)) + 1
			}
			if err := sc.Err(); err != nil {
				f.Close()
				return
			}
			f.Close()
			flusher.Flush()
		}
	} else if fi, err := os.Stat(path); err == nil {
		offset = fi.Size()
	}

	tick := time.NewTicker(watchPoll)
	defer tick.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		// A file that shrank was replaced by a new run; start it from the top.
		if fi, err := os.Stat(path); err == nil && fi.Size() < offset {
			offset = 0
		}
		f, err := os.Open(path)
		if err != nil {
			if time.Since(last) >= watchKeepalive {
				fmt.Fprint(w, ": still watching\n\n")
				flusher.Flush()
				last = time.Now()
			}
			continue
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			continue
		}
		reader := bufio.NewReader(f)
		wrote := false
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 && line[len(line)-1] == '\n' {
				offset += int64(len(line))
				if writeFrame(w, bytesTrimNL(line)) {
					wrote = true
				}
			}
			if err != nil {
				break
			}
		}
		f.Close()
		if wrote {
			flusher.Flush()
			last = time.Now()
			continue
		}
		if time.Since(last) >= watchKeepalive {
			fmt.Fprint(w, ": still watching\n\n")
			flusher.Flush()
			last = time.Now()
		}
	}
}

// writeFrame emits one recorded line as an SSE frame. The line is forwarded
// verbatim when it is valid JSON, so a watcher sees exactly what the run wrote.
func writeFrame(w io.Writer, line []byte) bool {
	line = bytesTrimSpace(line)
	if len(line) == 0 {
		return true
	}
	var probe map[string]any
	if err := json.Unmarshal(line, &probe); err != nil {
		// A reader can catch the writer mid-line; skip it, the next poll gets
		// the completed line only if it was written as one.
		return true
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", line); err != nil {
		return false
	}
	return true
}

func bytesTrimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func bytesTrimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	return bytesTrimNL(b)
}

// watchEvents is used by tests and by any caller that wants the recorded run as
// data instead of a stream.
func watchEvents(dir string) ([]progress.Event, error) {
	return progress.ReadFile(filepath.Join(dir, ProgressFile))
}
