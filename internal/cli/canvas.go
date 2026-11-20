package cli

import "strings"

// canvas is a fixed-size grid of runes.
//
// Drawing into a grid first keeps a terminal frame to a single write, so the
// stream of progress lines can never tear the layout mid-redraw. It also makes
// layout testable without a terminal: a frame is just a string.
// ellipsisRune marks text cut by fit or putClip.
const ellipsisRune = '\u2026'

type canvas struct {
	w, h  int
	cells [][]rune
}

func newCanvas(w, h int) *canvas {
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	c := &canvas{w: w, h: h, cells: make([][]rune, h)}
	for y := range c.cells {
		row := make([]rune, w)
		for x := range row {
			row[x] = ' '
		}
		c.cells[y] = row
	}
	return c
}

func (c *canvas) set(x, y int, r rune) {
	if x < 0 || y < 0 || x >= c.w || y >= c.h {
		return
	}
	c.cells[y][x] = r
}

// put writes s at x,y, clipped at the right edge. Tab becomes a space so a
// stray tab cannot shift a whole row.
func (c *canvas) put(x, y int, s string) {
	if y < 0 || y >= c.h {
		return
	}
	for _, r := range s {
		if x >= c.w {
			return
		}
		if r == '\t' {
			r = ' '
		}
		c.set(x, y, r)
		x++
	}
}

func (c *canvas) hline(x, y, w int, r rune) {
	for i := 0; i < w; i++ {
		c.set(x+i, y, r)
	}
}

// putClip writes s at x,y, cut to at most width runes. Unlike fit it never pads,
// so it can be laid over an existing border without erasing it.
func (c *canvas) putClip(x, y, width int, s string) {
	if width <= 0 {
		return
	}
	r := []rune(s)
	if len(r) > width {
		if width == 1 {
			r = r[:1]
		} else {
			r = append(r[:width-1], ellipsisRune)
		}
	}
	c.put(x, y, string(r))
}

// box draws a rectangle with a title set into the top border. A title is written
// exactly as given, so callers pass the surrounding spaces they want.
func (c *canvas) box(x, y, w, h int, title string) {
	if w < 2 || h < 2 {
		return
	}
	c.hline(x, y, w, '─')
	c.hline(x, y+h-1, w, '─')
	for i := 1; i < h-1; i++ {
		c.set(x, y+i, '│')
		c.set(x+w-1, y+i, '│')
	}
	c.set(x, y, '┌')
	c.set(x+w-1, y, '┐')
	c.set(x, y+h-1, '└')
	c.set(x+w-1, y+h-1, '┘')
	if title != "" {
		c.putClip(x+1, y, w-2, title)
	}
}

// String returns the grid as plain text, one row per line. Used by tests and by
// the demo renderer.
func (c *canvas) String() string {
	var b strings.Builder
	for y, row := range c.cells {
		if y > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(strings.TrimRight(string(row), " "))
	}
	return b.String()
}

// Render returns the grid ready to write to a terminal: cursor home, then rows
// separated by CRLF so the frame does not stair-step, then clear to the end of
// the screen so nothing from a shorter previous frame survives.
func (c *canvas) Render() string {
	var b strings.Builder
	b.WriteString("\033[H")
	for y, row := range c.cells {
		if y > 0 {
			b.WriteString("\r\n")
		}
		b.WriteString(string(row))
	}
	b.WriteString("\033[J")
	return b.String()
}

// fit clips or pads s to exactly width runes, marking a cut with an ellipsis.
// It works on runes, so box-drawing characters and non-ASCII labels keep the
// alignment the rest of the frame depends on.
func fit(s string, width int) string {
	if width <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) > width {
		if width == 1 {
			return string(r[:1])
		}
		return string(r[:width-1]) + string(ellipsisRune)
	}
	if len(r) == width {
		return s
	}
	return s + strings.Repeat(" ", width-len(r))
}

// trim tail-trims a log line for display inside a pane.
func trim(s string) string { return strings.TrimRight(s, " \t") }
