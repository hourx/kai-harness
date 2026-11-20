package program

import (
	"context"
	"sort"

	"github.com/hourx/kai-harness/pkg/netx"
)

// ParserFunc reads a program's policy into an Intake. A driver manifest names
// one of these by id; the implementation may live anywhere as long as it is
// registered before use, so a new platform can add a reader without the core
// learning the platform's name.
type ParserFunc func(ctx context.Context, c *netx.Client, raw string, opts FetchOptions) (*Intake, error)

var parsers = map[string]ParserFunc{}

// RegisterParser installs a reader under an id. Registering an empty id or a
// nil function is a programming error, not a runtime condition.
func RegisterParser(id string, fn ParserFunc) {
	if id == "" || fn == nil {
		panic("program: RegisterParser needs a non-empty id and a function")
	}
	parsers[id] = fn
}

// ParserFor returns the registered reader for an id.
func ParserFor(id string) (ParserFunc, bool) {
	fn, ok := parsers[id]
	return fn, ok
}

// ParserIDs lists registered readers, ordered.
func ParserIDs() []string {
	out := make([]string, 0, len(parsers))
	for id := range parsers {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func init() {
	// The HackerOne reader takes a handle; a URL is accepted and reduced to one
	// so the same entry point serves `kai intake temu` and a pasted URL.
	RegisterParser("hackerone", func(ctx context.Context, c *netx.Client, raw string, _ FetchOptions) (*Intake, error) {
		handle, _, err := HackerOneHandle(raw)
		if err != nil {
			return nil, err
		}
		return FetchHackerOne(ctx, c, handle)
	})

	// The generic reader fetches a policy page and follows a bounded number of
	// documentation links. It is the whole implementation for platforms that
	// publish scope as HTML, and the fallback for a self-hosted program.
	RegisterParser("generic", func(ctx context.Context, c *netx.Client, raw string, opts FetchOptions) (*Intake, error) {
		return FetchWeb(ctx, c, raw, opts)
	})
}
