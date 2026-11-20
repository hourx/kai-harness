package cli

import (
	"strings"
	"testing"
)

func TestCanvasIsBlankAndCorrectSize(t *testing.T) {
	c := newCanvas(10, 3)
	if got := c.String(); got != "\n\n" {
		t.Fatalf("blank canvas = %q", got)
	}
	rows := strings.Split(c.String(), "\n")
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
}

func TestCanvasClipsAtEdges(t *testing.T) {
	c := newCanvas(5, 2)
	c.put(3, 0, "abcdef") // runs past the right edge
	c.put(-2, 1, "xy")    // starts left of the canvas: those runes land nowhere
	c.put(4, 1, "z")      // last column: must land
	c.set(99, 0, 'Z')     // out of bounds: must not panic
	c.set(0, -1, 'Z')     // out of bounds: must not panic
	if got := c.String(); got != "   ab\n    z" {
		t.Fatalf("clip = %q", got)
	}
}

func TestCanvasBoxAndTitle(t *testing.T) {
	c := newCanvas(12, 4)
	c.box(0, 0, 12, 4, " TOP ")
	want := "" +
		"┌ TOP ─────┐\n" +
		"│          │\n" +
		"│          │\n" +
		"└──────────┘"
	if got := strings.TrimRight(c.String(), "\n"); got != want {
		t.Fatalf("box =\n%s\nwant\n%s", got, want)
	}
}

func TestCanvasBoxTooSmallIsNoop(t *testing.T) {
	c := newCanvas(8, 2)
	c.box(0, 0, 1, 1, "x")
	if got := c.String(); got != "\n" {
		t.Fatalf("tiny box drew something: %q", got)
	}
}

func TestFitPadsCutsAndKeepsWidth(t *testing.T) {
	if got := fit("abc", 5); got != "abc  " {
		t.Fatalf("pad = %q", got)
	}
	if got := fit("abcdef", 5); got != "abcd…" {
		t.Fatalf("cut = %q", got)
	}
	if got := fit("abcde", 5); got != "abcde" {
		t.Fatalf("exact = %q", got)
	}
	if got := fit("ab", 1); got != "a" {
		t.Fatalf("width 1 = %q", got)
	}
	if got := fit("ab", 0); got != "" {
		t.Fatalf("width 0 = %q", got)
	}
	if got := fit("héllo wörld", 6); len([]rune(got)) != 6 {
		t.Fatalf("runes = %q (%d runes)", got, len([]rune(got)))
	}
}

func TestRenderUsesCRLFAndClears(t *testing.T) {
	c := newCanvas(3, 2)
	c.put(0, 0, "ab")
	c.put(0, 1, "cd")
	got := c.Render()
	if !strings.HasPrefix(got, "\033[H") || !strings.HasSuffix(got, "\033[J") {
		t.Fatalf("render = %q", got)
	}
	if strings.Count(got, "\r\n") != 1 {
		t.Fatalf("expected exactly one CRLF: %q", got)
	}
}
