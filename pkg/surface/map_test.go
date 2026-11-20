package surface

import "testing"

// A URL assembled in JavaScript can end up in the surface map verbatim. The
// module name must stay something an operator can act on.
func TestModuleSkipsJavaScriptWreckage(t *testing.T) {
	cases := map[string]string{
		// The wreckage is skipped; the module is whatever plausible segment
		// follows it, or the root when nothing does.
		`/en/search/?text=" + "`:             "en",
		`/api/v1/" + endpoint + "/x`:         "x",
		`/v2/${tenant}/orders`:               "orders",
		`/api/v1/" + id + "/" + field + "/"`: "/",
		"/api/v1/orders":                     "orders",
		"/rest/users":                        "users",
		"/":                                  "/",
		"":                                   "/",
	}
	for in, want := range cases {
		if got := Module(in); got != want {
			t.Errorf("Module(%q) = %q, want %q", in, got, want)
		}
	}
}
