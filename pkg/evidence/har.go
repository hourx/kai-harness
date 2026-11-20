package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// HAR 1.2 import: a captured browser or proxy session enters the evidence index
// in bulk, so a session the operator already paid for does not have to be
// replayed request by request.
//
// One HAR entry becomes one evidence item that carries BOTH sides of the
// exchange: the request headers/body and the response, in a single blob. That is
// the pairing invariant — a finding may not cite a response without the request
// that produced it, and vice versa.

// HAR is the subset of HAR 1.2 this package reads. Unknown fields are ignored,
// so a capture from any tool that honours the spec still imports.
type HAR struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string `json:"version"`
	Creator struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"creator"`
	Entries []harEntry `json:"entries"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time,omitempty"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
}

type harRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	HTTPVersion string         `json:"httpVersion,omitempty"`
	Headers     []harNameValue `json:"headers"`
	QueryString []harNameValue `json:"queryString,omitempty"`
	PostData    *harPostData   `json:"postData,omitempty"`
}

type harPostData struct {
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
}

type harResponse struct {
	Status      int            `json:"status"`
	StatusText  string         `json:"statusText,omitempty"`
	HTTPVersion string         `json:"httpVersion,omitempty"`
	Headers     []harNameValue `json:"headers"`
	Content     harContent     `json:"content"`
}

type harContent struct {
	Size     int64  `json:"size,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HAROptions tunes an import.
type HAROptions struct {
	// Redact replaces the value of credential-bearing headers with a length
	// marker. On by default; the raw capture stays on disk untouched.
	Redact bool
	// Limit caps how many entries are imported (0 = every entry).
	Limit int
	// Label names the capture in each item's note.
	Label string
}

// HARStats reports what an import actually did, so a run that silently imported
// nothing cannot look like success.
type HARStats struct {
	Version  string         `json:"version"`
	Creator  string         `json:"creator"`
	Entries  int            `json:"entries"`
	Kept     int            `json:"kept"`
	Added    int            `json:"added"`
	Existing int            `json:"existing"`
	Skipped  int            `json:"skipped"`
	Why      map[string]int `json:"skipped_why,omitempty"`
}

var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"x-csrf-token":        true,
	"x-xsrf-token":        true,
	"api-key":             true,
}

// HARItem is one imported entry: the catalogue record plus the bytes behind it.
// They travel together because an item whose blob is missing is a claim with no
// evidence attached.
type HARItem struct {
	Item Item   `json:"item"`
	Raw  []byte `json:"-"`
}

// HAREntries turns a capture into evidence items without touching disk.
func HAREntries(data []byte, opt HAROptions) ([]HARItem, HARStats, error) {
	var h HAR
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, HARStats{}, fmt.Errorf("har: not valid JSON: %w", err)
	}
	st := HARStats{Version: h.Log.Version, Creator: h.Log.Creator.Name, Why: map[string]int{}}
	if h.Log.Version == "" && len(h.Log.Entries) == 0 {
		return nil, st, errors.New("har: no log.version and no log.entries — this is not a HAR file")
	}
	st.Entries = len(h.Log.Entries)

	var items []HARItem
	for i, e := range h.Log.Entries {
		if opt.Limit > 0 && len(items) >= opt.Limit {
			st.Skipped++
			st.Why["limit reached"]++
			continue
		}
		it, raw, why := harItem(e, i, opt)
		if why != "" {
			st.Skipped++
			st.Why[why]++
			continue
		}
		it.ID = ""
		items = append(items, HARItem{Item: it, Raw: raw})
	}
	st.Kept = len(items)
	return items, st, nil
}

// harItem converts one entry. An empty reason means the entry is usable.
func harItem(e harEntry, i int, opt HAROptions) (Item, []byte, string) {
	raw := strings.TrimSpace(e.Request.URL)
	if raw == "" {
		return Item{}, nil, "no request url"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Item{}, nil, "unparseable request url"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Item{}, nil, "non-http scheme"
	}
	method := strings.ToUpper(strings.TrimSpace(e.Request.Method))
	if method == "" {
		method = "GET"
	}

	// Redact once, on the entry itself: the catalogue headers and the stored
	// bytes must agree, or the blob quietly keeps what the index claims to hide.
	if opt.Redact {
		e = redactEntry(e)
	}

	headers := make([]string, 0, len(e.Request.Headers)+len(e.Response.Headers))
	for _, h := range e.Request.Headers {
		headers = append(headers, "req:"+h.Name+": "+h.Value)
	}
	for _, h := range e.Response.Headers {
		headers = append(headers, "res:"+h.Name+": "+h.Value)
	}

	blob, err := json.Marshal(entryBlob{Index: i + 1, Entry: e, Redacted: opt.Redact})
	if err != nil {
		return Item{}, nil, "entry cannot be re-marshalled"
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	if t, err := time.Parse(time.RFC3339, e.StartedDateTime); err == nil {
		ts = t.UTC().Format(time.RFC3339)
	}

	label := opt.Label
	if label == "" {
		label = "har"
	}
	return Item{
		TS:      ts,
		Kind:    "response",
		Host:    u.Host,
		Method:  method,
		Path:    u.RequestURI(),
		Target:  raw,
		Status:  e.Response.Status,
		Headers: headers,
		Note:    fmt.Sprintf("%s entry %d: %s %s", label, i+1, method, raw),
	}, blob, ""
}

type entryBlob struct {
	Index    int      `json:"entry"`
	Entry    harEntry `json:"har"`
	Redacted bool     `json:"headers_redacted,omitempty"`
}

// redactEntry returns a copy of the entry whose credential-bearing headers carry
// a length marker instead of the value. Length is kept because it is often the
// only clue about which token was in play; the value never is.
func redactEntry(e harEntry) harEntry {
	e.Request.Headers = redactHeaders(e.Request.Headers)
	e.Response.Headers = redactHeaders(e.Response.Headers)
	return e
}

func redactHeaders(in []harNameValue) []harNameValue {
	if len(in) == 0 {
		return in
	}
	out := make([]harNameValue, len(in))
	copy(out, in)
	for i := range out {
		if !sensitiveHeaders[strings.ToLower(strings.TrimSpace(out[i].Name))] || out[i].Value == "" {
			continue
		}
		out[i].Value = fmt.Sprintf("REDACTED(len=%d)", len(out[i].Value))
	}
	return out
}

// ImportHAR writes every usable entry of a capture into a program's evidence
// index. Re-importing the same capture is a no-op: item IDs are content-derived,
// so the second run reports the entries as existing rather than duplicating them.
func ImportHAR(pDir string, data []byte, rawName string, opt HAROptions) (HARStats, error) {
	items, st, err := HAREntries(data, opt)
	if err != nil {
		return st, err
	}
	for i, it := range items {
		name := rawName
		if name == "" {
			name = "capture.har"
		}
		_, existed, err := Capture(pDir, it.Item, it.Raw, fmt.Sprintf("%s.%d.json", name, i+1))
		if err != nil {
			return st, err
		}
		if existed {
			st.Existing++
		} else {
			st.Added++
		}
	}
	return st, nil
}

// MarkdownHAR renders an import report for a terminal.
func MarkdownHAR(st HARStats, label string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# HAR import: %s\n\n", label)
	fmt.Fprintf(&b, "- har version: %s (%s)\n", st.Version, st.Creator)
	fmt.Fprintf(&b, "- entries: %d\n- kept: %d\n- added: %d\n- already known: %d\n- skipped: %d\n",
		st.Entries, st.Kept, st.Added, st.Existing, st.Skipped)
	if len(st.Why) > 0 {
		b.WriteString("\n## Skipped because\n\n")
		for _, k := range sortedKeys(st.Why) {
			fmt.Fprintf(&b, "- %s: %d\n", k, st.Why[k])
		}
	}
	return b.String()
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
