package strutil

import (
	"reflect"
	"testing"
)

func TestDash(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "—"},
		{"   ", "—"},
		{"\t\n", "—"},
		{"ok", "ok"},
		{" ok ", " ok "},
	}
	for _, c := range cases {
		if got := Dash(c.in); got != c.want {
			t.Errorf("Dash(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestUnique(t *testing.T) {
	got := Unique([]string{"b", "", "a", "b", "a", ""})
	want := []string{"b", "a"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Unique = %v, want %v (order preserved, blanks dropped)", got, want)
	}
	if got := Unique(nil); len(got) != 0 {
		t.Errorf("Unique(nil) = %v, want empty", got)
	}
}

func TestUniqueGroups(t *testing.T) {
	got := UniqueGroups([]string{"a", "b"}, nil, []string{"b", "c", ""})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("UniqueGroups = %v, want %v", got, want)
	}
}

func TestUniqueSorted(t *testing.T) {
	got := UniqueSorted([]string{"c", "a", "", "b", "a"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("UniqueSorted = %v, want %v", got, want)
	}
}
