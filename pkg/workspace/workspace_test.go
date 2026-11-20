package workspace

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestExactHostsAndDeriveDomains(t *testing.T) {
	t.Setenv("KAI_HOME", t.TempDir())
	p, err := Create("example", Meta{})
	if err != nil {
		t.Fatal(err)
	}
	scope := `# generated rules
api.example.com
*.example.com
shop.app
203.0.113.0/24
https://other.test/path/*
# a comment
`
	if err := os.WriteFile(filepath.Join(p.Dir, "scope.txt"), []byte(scope), 0o600); err != nil {
		t.Fatal(err)
	}
	got := p.ExactHosts()
	want := []string{"api.example.com", "shop.app"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExactHosts = %v, want %v", got, want)
	}
	if d := p.DeriveDomains(); !reflect.DeepEqual(d, []string{"example.com"}) {
		t.Errorf("DeriveDomains = %v, want [example.com]", d)
	}
}

func TestExactHostsEmpty(t *testing.T) {
	t.Setenv("KAI_HOME", t.TempDir())
	p, err := Create("empty", Meta{})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ExactHosts(); len(got) != 0 {
		t.Errorf("ExactHosts = %v, want empty", got)
	}
}
