package ui

import (
	"bufio"
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/term"

	"github.com/devvmhq/devvm/internal/msg"
)

// Choice is one of the items Pick shows: a name, what it is, and whether
// it's chosen. A Fixed one is shown greyed out as it is: the cursor skips
// it, and it can't be toggled.
type Choice struct {
	Name, Desc string
	On         bool
	Fixed      bool
}

// Section is a heading and the choices under it, as Pick shows them. A
// section whose Heading is the zero message has no heading.
type Section struct {
	Heading msg.M
	Choices []Choice
}

// rawTerminal puts the terminal devvm reads from into raw mode, returning
// what undoes it.
func rawTerminal() (restore func(), err error) {
	old, err := term.MakeRaw(fd(os.Stdin))
	if err != nil {
		return nil, err
	}
	return func() { _ = term.Restore(fd(os.Stdin), old) }, nil
}

// Pick shows the sections' choices under help, each section under its
// heading, and lets the user toggle them: up and down (or k and j) move
// over every choice but the fixed ones, space toggles, enter confirms. It
// returns the sections as chosen. Without a terminal to read from and
// print to, it returns them as given. Ctrl+C ends the run as interrupted.
func (u *UI) Pick(help msg.M, sections []Section) []Section {
	out := make([]Section, len(sections))
	for i, s := range sections {
		out[i] = Section{Heading: s.Heading, Choices: slices.Clone(s.Choices)}
	}
	u.pick(help, out, false)
	return out
}

// PickOne shows the choices under help and lets the user choose one: up
// and down (or k and j) move the choice, enter confirms. It starts from
// the first that's on and returns the index of the one chosen. Without a
// terminal to read from and print to, that's the one it started from.
// Ctrl+C ends the run as interrupted.
func (u *UI) PickOne(help msg.M, choices []Choice) int {
	out := slices.Clone(choices)
	start := max(slices.IndexFunc(out, func(c Choice) bool { return c.On }), 0)
	for i := range out {
		out[i].On = i == start
	}
	u.pick(help, []Section{{Choices: out}}, true)
	return max(slices.IndexFunc(out, func(c Choice) bool { return c.On }), 0)
}

// pick runs pickLoop on the terminal, the sections' choices changed in
// place; where it isn't shown (CanPick) it leaves them as they are.
func (u *UI) pick(help msg.M, sections []Section, one bool) {
	n := 0
	for _, s := range sections {
		n += len(s.Choices)
	}
	if n == 0 || !u.CanPick() {
		return
	}
	restore, err := u.rawInput()
	if err != nil {
		return
	}
	// In raw mode a line ends with \r\n; the cursor is hidden meanwhile.
	u.write(u.stdout, strings.ReplaceAll(u.outStyle.message(help), "\n", "\r\n")+"\r\n\033[?25l")
	ok := u.pickLoop(u.stdin, sections, one)
	u.write(u.stdout, "\033[?25h")
	restore()
	if !ok {
		u.write(u.stderr, "\n")
		u.interrupted.Store(true)
		exit(InterruptedCode)
	}
}

// picking is what pickLoop draws and moves over: every choice in order,
// and the ones the cursor can reach.
type picking struct {
	sections []Section
	rows     []*Choice
	movable  []int // indexes into rows
	one      bool
}

func newPicking(sections []Section, one bool) *picking {
	p := &picking{sections: sections, one: one}
	for i := range sections {
		cs := sections[i].Choices
		for j := range cs {
			c := &cs[j]
			if !c.Fixed {
				p.movable = append(p.movable, len(p.rows))
			}
			p.rows = append(p.rows, c)
		}
	}
	return p
}

// draw writes the headings and rows, the cursor at the movable row cur
// (-1 for none), and returns how many lines it wrote.
func (p *picking) draw(s style, cur int) (string, int) {
	open, on, closed := "[", "x", "]"
	if p.one {
		open, on, closed = "(", "*", ")"
	}
	var b strings.Builder
	lines, row := 0, 0
	// Names line up at 10 columns, or the longest name's, such as a host's.
	width := 10
	for _, c := range p.rows {
		width = max(width, len([]rune(msg.OneLine(c.Name))))
	}
	for _, sec := range p.sections {
		if sec.Heading.ID() != "" {
			fmt.Fprintf(&b, "\033[2K%s\r\n", s.paint(sgrBold, msg.OneLine(s.line(sec.Heading))))
			lines++
		}
		for _, c := range sec.Choices {
			mark, ptr := " ", " "
			if c.On {
				mark = on
			}
			if cur >= 0 && p.movable[cur] == row {
				ptr = ">"
			}
			line := fmt.Sprintf("%s %s%s%s %-*s %s", ptr, open, mark, closed, width, msg.OneLine(c.Name), msg.OneLine(c.Desc))
			if c.Fixed {
				line = s.paint(sgrDim, line)
			}
			b.WriteString("\033[2K" + line + "\r\n")
			lines++
			row++
		}
	}
	return b.String(), lines
}

// pickLoop draws the choices and reads keys until enter (or the end of
// the input), toggling choices in place, or with one, moving the one
// that's on with the cursor. It's false on Ctrl+C.
func (u *UI) pickLoop(in *bufio.Reader, sections []Section, one bool) bool {
	p := newPicking(sections, one)
	n := len(p.movable)
	cur := -1
	if n > 0 {
		cur = 0
	}
	if one && n > 0 {
		cur = max(slices.IndexFunc(p.movable, func(r int) bool { return p.rows[r].On }), 0)
	}
	for {
		out, lines := p.draw(u.outStyle, cur)
		u.write(u.stdout, out)
		key, err := in.ReadByte()
		if err != nil {
			return true
		}
		switch key {
		case 0x03: // Ctrl+C: raw mode turns it into input
			return false
		case '\r', '\n':
			return true
		case ' ':
			if !one && cur >= 0 {
				c := p.rows[p.movable[cur]]
				c.On = !c.On
			}
		case 'k':
			cur = step(cur, n, -1)
		case 'j':
			cur = step(cur, n, 1)
		case 0x1b: // an arrow: ESC [ A or ESC [ B
			if seq, err := in.Peek(2); err == nil && seq[0] == '[' {
				switch seq[1] {
				case 'A':
					cur = step(cur, n, -1)
				case 'B':
					cur = step(cur, n, 1)
				}
				_, _ = in.Discard(2)
			}
		}
		if one {
			for i, r := range p.movable {
				p.rows[r].On = i == cur
			}
		}
		u.write(u.stdout, fmt.Sprintf("\033[%dA", lines))
	}
}

// step moves the cursor cur by d over n rows, wrapping; -1 (none) stays.
func step(cur, n, d int) int {
	if cur < 0 {
		return cur
	}
	return (cur + n + d) % n
}
