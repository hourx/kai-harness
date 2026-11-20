// Package evidence captures the raw proof a finding rests on.
//
// One directory holds an append-only index plus the blobs themselves. Every
// entry carries a content hash, so a report drafted months later can be tied to
// bytes that cannot silently change. Nothing here talks to the network and
// nothing here decides whether something is a vulnerability — evidence is what
// an operator or an agent observed, recorded verbatim.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	dirName   = "evidence"
	indexName = "index.json"
	fileMode  = 0o600
	dirMode   = 0o700
)

// Kinds is the accepted set for Item.Kind.
var Kinds = []string{"response", "request", "screenshot", "poc", "note", "log"}

// Item is one piece of evidence: what was sent, what came back, and where the
// raw bytes live.
type Item struct {
	ID         string   `json:"id"`
	TS         string   `json:"ts"`
	Kind       string   `json:"kind"`
	Host       string   `json:"host,omitempty"`
	Method     string   `json:"method,omitempty"`
	Path       string   `json:"path,omitempty"`
	Target     string   `json:"target,omitempty"`
	Status     int      `json:"status,omitempty"`
	Headers    []string `json:"headers,omitempty"`
	BodySHA256 string   `json:"body_sha256,omitempty"`
	BodyBytes  int64    `json:"body_bytes,omitempty"`
	Blob       string   `json:"blob,omitempty"`
	BlobSHA256 string   `json:"blob_sha256,omitempty"`
	BlobBytes  int64    `json:"blob_bytes,omitempty"`
	Note       string   `json:"note,omitempty"`
	Finding    string   `json:"finding_id,omitempty"`
}

// Dir returns the evidence directory of a program workspace.
func Dir(pDir string) string { return filepath.Join(pDir, dirName) }

// IndexPath returns the path of the evidence index.
func IndexPath(pDir string) string { return filepath.Join(Dir(pDir), indexName) }

// Load reads the index in a stable order (oldest first, ID as tie-break).
func Load(pDir string) ([]Item, error) {
	b, err := os.ReadFile(IndexPath(pDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var items []Item
	if err := json.Unmarshal(b, &items); err != nil {
		return nil, fmt.Errorf("evidence index %s: %w", IndexPath(pDir), err)
	}
	Sort(items)
	return items, nil
}

// Sort orders items deterministically: timestamp, then ID.
func Sort(items []Item) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].TS != items[j].TS {
			return items[i].TS < items[j].TS
		}
		return items[i].ID < items[j].ID
	})
}

// Find returns one item by ID (exact match, case-sensitive).
func Find(pDir, id string) (Item, bool, error) {
	items, err := Load(pDir)
	if err != nil {
		return Item{}, false, err
	}
	for _, it := range items {
		if it.ID == id {
			return it, true, nil
		}
	}
	return Item{}, false, nil
}

// Capture writes one evidence item plus its blob and records it in the index.
//
// raw is the file content to preserve (may be nil for a note). rawName is used
// for the blob's suffix only. The ID is a deterministic digest of the item's
// identity plus its content, so capturing the same bytes twice is a no-op that
// returns the existing record instead of duplicating it.
func Capture(pDir string, it Item, raw []byte, rawName string) (Item, bool, error) {
	if err := validate(&it); err != nil {
		return Item{}, false, err
	}
	if it.TS == "" {
		it.TS = time.Now().UTC().Format(time.RFC3339)
	}
	if len(raw) > 0 {
		sum := sha256.Sum256(raw)
		it.BlobSHA256 = hex.EncodeToString(sum[:])
		it.BlobBytes = int64(len(raw))
		if it.Kind == "response" || it.Kind == "request" || it.Kind == "log" {
			it.BodySHA256 = it.BlobSHA256
			it.BodyBytes = it.BlobBytes
		}
	}
	it.ID = id(&it)

	existing, found, err := Find(pDir, it.ID)
	if err != nil {
		return Item{}, false, err
	}
	if found {
		return existing, true, nil
	}

	if err := os.MkdirAll(Dir(pDir), dirMode); err != nil {
		return Item{}, false, err
	}
	if len(raw) > 0 {
		blob := filepath.Join(dirName, it.ID+"-"+sanitize(rawName))
		if err := os.WriteFile(filepath.Join(pDir, blob), raw, fileMode); err != nil {
			return Item{}, false, err
		}
		it.Blob = blob
	}

	items, err := Load(pDir)
	if err != nil {
		return Item{}, false, err
	}
	items = append(items, it)
	Sort(items)
	if err := writeIndex(pDir, items); err != nil {
		return Item{}, false, err
	}
	// Read back: a successful write is not the same thing as a readable record.
	back, ok, err := Find(pDir, it.ID)
	if err != nil {
		return Item{}, false, err
	}
	if !ok || back.BlobSHA256 != it.BlobSHA256 {
		return Item{}, false, fmt.Errorf("evidence written but not readable back at %s", IndexPath(pDir))
	}
	return back, false, nil
}

// Attach links an existing evidence item to a finding ID.
func Attach(pDir, id, finding string) (Item, error) {
	items, err := Load(pDir)
	if err != nil {
		return Item{}, err
	}
	for i := range items {
		if items[i].ID == id {
			items[i].Finding = finding
			if err := writeIndex(pDir, items); err != nil {
				return Item{}, err
			}
			return items[i], nil
		}
	}
	return Item{}, fmt.Errorf("no evidence with id %q", id)
}

func validate(it *Item) error {
	if it.Kind == "" {
		return errors.New("evidence needs --kind " + strings.Join(Kinds, "|"))
	}
	ok := false
	for _, k := range Kinds {
		if it.Kind == k {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("unknown evidence kind %q — one of: %s", it.Kind, strings.Join(Kinds, ", "))
	}
	if it.Host == "" && it.Path == "" && it.Target == "" && it.Note == "" {
		return errors.New("evidence needs at least one of --host/--path/--target/--note")
	}
	return nil
}

func id(it *Item) string {
	h := sha256.New()
	for _, f := range []string{it.Kind, it.Host, it.Method, it.Path, it.Target, it.TS, it.BlobSHA256} {
		fmt.Fprintf(h, "%s\x00", f)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func sanitize(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return "blob"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

func writeIndex(pDir string, items []Item) error {
	if err := os.MkdirAll(Dir(pDir), dirMode); err != nil {
		return err
	}
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := IndexPath(pDir) + ".tmp"
	if err := os.WriteFile(tmp, b, fileMode); err != nil {
		return err
	}
	return os.Rename(tmp, IndexPath(pDir))
}

// Markdown renders the evidence list for a plan, a board or a report draft.
func Markdown(items []Item) string {
	if len(items) == 0 {
		return "_no evidence captured_\n"
	}
	var b strings.Builder
	for _, it := range items {
		b.WriteString("- `" + it.ID + "` " + it.TS + " **" + it.Kind + "**")
		if it.Method != "" || it.Host != "" || it.Path != "" {
			b.WriteString(fmt.Sprintf(" — `%s %s%s`", strings.TrimSpace(it.Method), it.Host, it.Path))
		}
		if it.Status != 0 {
			b.WriteString(fmt.Sprintf(" → HTTP %d", it.Status))
		}
		if it.BlobSHA256 != "" {
			b.WriteString(" sha256:" + short(it.BlobSHA256))
		}
		if it.Blob != "" {
			b.WriteString(" (" + it.Blob + ")")
		}
		if it.Finding != "" {
			b.WriteString(" → finding " + it.Finding)
		}
		if it.Note != "" {
			b.WriteString(" — " + it.Note)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func short(sum string) string {
	if len(sum) > 16 {
		return sum[:16]
	}
	return sum
}
