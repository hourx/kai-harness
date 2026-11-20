package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hourx/kai-harness/pkg/evidence"
	"github.com/hourx/kai-harness/pkg/workspace"
)

// kvFlag collects repeated string flags (--header 'K: V').
type kvFlag []string

func (k *kvFlag) String() string { return strings.Join(*k, ", ") }

func (k *kvFlag) Set(v string) error {
	*k = append(*k, v)
	return nil
}

// cmdEvidence captures the raw proof behind a finding. Files are stored with
// their content hash, so a report written later can be tied to bytes that cannot
// silently change.
func cmdEvidence(args []string) int {
	pos, rest := split(args, map[string]bool{
		"kind": true, "host": true, "method": true, "path": true, "status": true,
		"note": true, "target": true, "finding": true, "file": true,
		"har": true, "limit": true, "label": true,
	})
	fs := flag.NewFlagSet("evidence", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	kind := fs.String("kind", "", "one of: "+strings.Join(evidence.Kinds, "|"))
	host := fs.String("host", "", "host the evidence came from")
	method := fs.String("method", "", "HTTP method")
	path := fs.String("path", "", "path (with query if it matters)")
	status := fs.Int("status", 0, "observed HTTP status")
	note := fs.String("note", "", "one line of context")
	target := fs.String("target", "", "queue target this evidence belongs to")
	finding := fs.String("finding", "", "findings/ledger.json id this evidence supports")
	file := fs.String("file", "", "raw response/body to preserve")
	harPath := fs.String("har", "", "import every usable entry of a HAR capture (evidence import)")
	harLimit := fs.Int("limit", 0, "with --har: import at most N entries (0 = all)")
	harLabel := fs.String("label", "", "with --har: name this capture in each item's note")
	keepSecrets := fs.Bool("keep-secrets", false, "with --har: store credential header values instead of a length marker")
	var headers kvFlag
	fs.Var(&headers, "header", "response header line, repeatable")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if len(pos) < 1 {
		return fail(errors.New("usage: kai evidence <program> [list | add --kind K [...] | show <id> | attach <id> --finding F]"))
	}
	p, err := workspace.Open(pos[0])
	if err != nil {
		return fail(err)
	}
	sub := "list"
	if len(pos) > 1 {
		sub = pos[1]
	}
	id := ""
	if len(pos) > 2 {
		id = pos[2]
	}

	switch sub {
	case "list":
		items, err := evidence.Load(p.Dir)
		if err != nil {
			return fail(err)
		}
		fmt.Printf("%d evidence item(s) in %s\n\n", len(items), evidence.IndexPath(p.Dir))
		fmt.Print(evidence.Markdown(items))
		return 0

	case "add":
		it := evidence.Item{
			Kind:    *kind,
			Host:    *host,
			Method:  *method,
			Path:    *path,
			Target:  *target,
			Status:  *status,
			Note:    *note,
			Finding: *finding,
			Headers: headers,
		}
		var raw []byte
		rawName := ""
		if *file != "" {
			b, err := os.ReadFile(*file)
			if err != nil {
				return fail(err)
			}
			raw = b
			rawName = filepath.Base(*file)
		}
		got, existed, err := evidence.Capture(p.Dir, it, raw, rawName)
		if err != nil {
			return fail(err)
		}
		if existed {
			fmt.Printf("already captured: %s (%s, %s)\n", got.ID, got.Kind, got.TS)
			return 0
		}
		fmt.Printf("captured %s — %s\n", got.ID, got.Kind)
		if got.Blob != "" {
			fmt.Printf("  blob: %s (%d bytes, sha256 %s)\n", got.Blob, got.BlobBytes, got.BlobSHA256)
		}
		fmt.Printf("  index: %s\n", evidence.IndexPath(p.Dir))
		return 0

	case "show":
		if id == "" {
			return fail(errors.New("usage: kai evidence <program> show <id>"))
		}
		it, ok, err := evidence.Find(p.Dir, id)
		if err != nil {
			return fail(err)
		}
		if !ok {
			return fail(fmt.Errorf("no evidence with id %q in %s", id, p.Dir))
		}
		fmt.Print(evidence.Markdown([]evidence.Item{it}))
		return 0

	case "import":
		if *harPath == "" {
			return fail(errors.New("usage: kai evidence import <program> --har capture.har [--limit N] [--label name] [--keep-secrets]"))
		}
		blob, err := os.ReadFile(*harPath)
		if err != nil {
			return fail(err)
		}
		label := *harLabel
		if label == "" {
			label = filepath.Base(*harPath)
		}
		st, err := evidence.ImportHAR(p.Dir, blob, filepath.Base(*harPath), evidence.HAROptions{
			Redact: !*keepSecrets,
			Limit:  *harLimit,
			Label:  label,
		})
		if err != nil {
			return fail(err)
		}
		fmt.Print(evidence.MarkdownHAR(st, label))
		if st.Added+st.Existing == 0 {
			fmt.Fprintln(os.Stderr, "kai: the capture held no usable entry — nothing indexed")
			return 1
		}
		fmt.Printf("\nindex: %s\n", evidence.IndexPath(p.Dir))
		return 0

	case "attach":
		if id == "" || *finding == "" {
			return fail(errors.New("usage: kai evidence <program> attach <id> --finding F"))
		}
		it, err := evidence.Attach(p.Dir, id, *finding)
		if err != nil {
			return fail(err)
		}
		fmt.Printf("attached %s to finding %s\n", it.ID, it.Finding)
		return 0
	}
	return fail(errors.New("usage: kai evidence <program> [list | add --kind K [...] | import --har f | show <id> | attach <id> --finding F]"))
}
