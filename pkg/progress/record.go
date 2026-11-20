package progress

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Recorder writes run Events to disk as one JSON object per line, so a run can
// be watched after the fact — or live, by another process. Without it the Bus is
// in-process only and a reader like `kai serve` has nothing to tail.
//
// One file per run: an existing file is truncated when the run starts, because a
// watch that mixed two runs would misreport the current one.
type Recorder struct {
	mu   sync.Mutex
	path string
	f    *os.File
	w    *bufio.Writer
	err  error
}

// NewRecorder creates (or truncates) path and returns a Recorder writing there.
func NewRecorder(path string) (*Recorder, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	return &Recorder{path: path, f: f, w: bufio.NewWriter(f)}, nil
}

// Path is where the recorder writes.
func (r *Recorder) Path() string { return r.path }

// Write appends one event as a JSON line. A write failure is kept and reported
// once from Err: a run must not die because a watcher's log file is unavailable.
func (r *Recorder) Write(e Event) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil || r.w == nil {
		return
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	b, err := json.Marshal(e)
	if err != nil {
		r.err = err
		return
	}
	if _, err := r.w.Write(append(b, '\n')); err != nil {
		r.err = err
		return
	}
	if err := r.w.Flush(); err != nil {
		r.err = err
	}
}

// Close flushes and closes the file.
func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.w != nil {
		_ = r.w.Flush()
	}
	if r.f != nil {
		err := r.f.Close()
		r.f = nil
		r.w = nil
		return err
	}
	return nil
}

// Err reports the first write failure, if any.
func (r *Recorder) Err() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// Record subscribes rec to the bus and returns the function that stops
// recording and closes the file. The returned function blocks until everything
// already emitted has been written, so a caller can flush at the end of a run
// and know the record is complete.
//
// Some events can be dropped if the recorder falls behind: a subscription is
// buffered, and a losing write must never stall the run it is observing. The
// file is a record of what a watcher saw, not a transaction log.
func Record(b *Bus, rec *Recorder) func() {
	if b == nil || rec == nil {
		return func() {}
	}
	ch, cancel := b.Subscribe()
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case e := <-ch:
				rec.Write(e)
			case <-quit:
				// Drain what is already queued, close, and stop: the
				// subscription channel is never closed by the Bus.
				for {
					select {
					case e := <-ch:
						rec.Write(e)
					default:
						_ = rec.Close()
						return
					}
				}
			}
		}
	}()
	return func() {
		cancel()
		close(quit)
		<-done
	}
}

// ReadFile parses a recorded run back into events. A line that is not a complete
// JSON object (a reader caught the writer mid-line) is skipped rather than
// failing the read.
func ReadFile(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("reading %s: %w", path, err)
	}
	return out, nil
}
