package ui

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/devvmhq/devvm/internal/msg"
)

func choices() []Choice {
	return []Choice{{Name: "a", Desc: "first", On: true}, {Name: "b", Desc: "second", On: true}, {Name: "c", Desc: "third\x1b[2J"}}
}

func onOf(cs []Choice) []string {
	var on []string
	for _, c := range cs {
		if c.On {
			on = append(on, c.Name)
		}
	}
	return on
}

// pickTerminal makes u's Pick see terminals, with raw mode a no-op that
// counts its restores.
func pickTerminal(u *UI) *int {
	restored := 0
	u.stdinTTY, u.stdoutTTY = true, true
	u.rawInput = func() (func(), error) { return func() { restored++ }, nil }
	return &restored
}

// Each row's description starts in one column: 10 wide, or past the
// longest name, such as a host's.
func TestPickColumns(t *testing.T) {
	t.Parallel()
	p := newPicking([]Section{{Choices: []Choice{{Name: "a", Desc: "first"}, {Name: "registry.npmjs.org", Desc: "second"}}}}, false)
	out, _ := p.draw(style{}, -1)
	if !strings.Contains(out, "  [ ] a                  first\r\n") || !strings.Contains(out, "  [ ] registry.npmjs.org second\r\n") {
		t.Errorf("drew %q", out)
	}
	short := newPicking([]Section{{Choices: choices()[:2]}}, false)
	if out, _ := short.draw(style{}, -1); !strings.Contains(out, "  [x] a          first\r\n") {
		t.Errorf("short names: drew %q", out)
	}
}

// redraw is a cursor move back up, as pickLoop writes it before a
// redraw.
var redraw = regexp.MustCompile(`\x1b\[(\d+)A`)

// In a terminal of 60 by 20, a list of 200 hosts, one of them 253
// characters long, draws each line within the width, its long name cut
// from the left so its domain shows, and scrolls in a window of the same
// lines every time, with how many more there are above and below, so a
// redraw never leaves a line of the last one behind. a ticks every row,
// and again unticks them all.
func TestPickFitsTheTerminal(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 236) + ".attacker.example" // 253
	many := []Choice{{Name: long, Desc: "1 connection"}}
	for i := range 199 {
		many = append(many, Choice{Name: "h" + strconv.Itoa(i) + ".example.com:443", Desc: strings.Repeat("d", 80)})
	}
	for _, tc := range []struct {
		keys string
		on   int
	}{{strings.Repeat("j", 150) + "a\r", 200}, {"aa\r", 0}, {strings.Repeat("k", 3) + " \r", 1}} {
		u, out, _ := testUI(t, tc.keys)
		pickTerminal(u)
		u.termSize = func() (int, int) { return 60, 20 }
		got := u.Pick(msg.MsgUnknown("x"), []Section{{Choices: many}})[0].Choices
		if n := len(onOf(got)); n != tc.on {
			t.Errorf("%q: %d on, want %d", tc.keys, n, tc.on)
		}
		s := out.String()
		moves := redraw.FindAllStringSubmatch(s, -1)
		if len(moves) == 0 {
			t.Fatalf("%q: no redraw", tc.keys)
		}
		for _, m := range moves {
			if m[1] != moves[0][1] {
				t.Errorf("%q: redraws of %s and %s lines: one leaves lines behind", tc.keys, moves[0][1], m[1])
			}
		}
		if n, _ := strconv.Atoi(moves[0][1]); n > 20-2 {
			t.Errorf("%q: %d lines, under a help line, in a terminal of 20", tc.keys, n)
		}
		plain := redraw.ReplaceAllString(strings.NewReplacer("\x1b[2K", "", "\x1b[?25l", "", "\x1b[?25h", "").Replace(s), "")
		for line := range strings.SplitSeq(plain, "\r\n") {
			if runes(line) >= 60 {
				t.Errorf("%q: a line of %d columns in 60: %q", tc.keys, runes(line), line)
			}
		}
		if !strings.Contains(plain, "attacker.example") || strings.Contains(plain, long) {
			t.Errorf("%q: the long name isn't cut from the left", tc.keys)
		}
		if !strings.Contains(plain, "pick_more count=") {
			t.Errorf("%q: no line says how many more", tc.keys)
		}
	}
}

// Where the terminal won't go into raw mode, PickChecked says why and
// leaves the choices as they were; Pick goes on with them.
func TestPickCheckedRawFails(t *testing.T) {
	t.Parallel()
	u, _, _ := testUI(t, "")
	pickTerminal(u)
	u.rawInput = func() (func(), error) { return nil, errors.New("no tty") }
	got, err := u.PickChecked(msg.MsgUnknown("x"), []Section{{Choices: choices()}})
	if msg.NamesOf(err) != "pick_failed reason=no tty" || !slices.Equal(onOf(got[0].Choices), []string{"a", "b"}) {
		t.Errorf("PickChecked = %q, %v", onOf(got[0].Choices), msg.NamesOf(err))
	}
}

func TestPickKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, keys string
		want       []string
	}{
		{"enter keeps them", "\r", []string{"a", "b"}},
		{"space toggles the first", " \r", []string{"b"}},
		{"j and space", "j \r", []string{"a"}},
		{"down arrow twice, space", "\x1b[B\x1b[B \r", []string{"a", "b", "c"}},
		{"up wraps to the last", "\x1b[A \r", []string{"a", "b", "c"}},
		{"k wraps, j back", "kj \r", []string{"b"}},
		{"other keys do nothing", "xq\x1b[C\r", []string{"a", "b"}},
		{"the end of input confirms", " ", []string{"b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u, out, _ := testUI(t, tc.keys)
			restored := pickTerminal(u)
			in := choices()
			got := u.Pick(msg.MsgUnknown("x"), []Section{{Choices: in}})[0].Choices
			if !slices.Equal(onOf(got), tc.want) {
				t.Errorf("chosen %q, want %q", onOf(got), tc.want)
			}
			if !slices.Equal(onOf(in), []string{"a", "b"}) {
				t.Error("Pick changed its argument")
			}
			if *restored != 1 {
				t.Errorf("raw mode undone %d times, want 1", *restored)
			}
			s := out.String()
			if !strings.HasPrefix(s, "msg_unknown name=x\r\n\033[?25l") || !strings.HasSuffix(s, "\033[?25h") {
				t.Errorf("output %q: no help first, or the cursor not shown again", s)
			}
			if !strings.Contains(s, "> [x] a          first\r\n") || strings.Contains(s, "\x1b[2J") {
				t.Errorf("output %q: rows not drawn, or a control sequence from a description", s)
			}
		})
	}
}

func TestPickOneKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, keys string
		start      int // the choice on; -1 for none
		want       int
	}{
		{"enter keeps the current", "\r", 1, 1},
		{"none on starts at the first", "\r", -1, 0},
		{"j moves down", "j\r", 0, 1},
		{"down arrow twice", "\x1b[B\x1b[B\r", 0, 2},
		{"up wraps to the last", "\x1b[A\r", 0, 2},
		{"k from the current", "k\r", 2, 1},
		{"space and other keys do nothing", " xq\x1b[C\r", 1, 1},
		{"the end of input confirms", "j", 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u, out, _ := testUI(t, tc.keys)
			restored := pickTerminal(u)
			in := []Choice{{Name: "a", Desc: "first"}, {Name: "b", Desc: "second"}, {Name: "c", Desc: "third"}}
			if tc.start >= 0 {
				in[tc.start].On = true
			}
			if got := u.PickOne(msg.MsgUnknown("x"), in); got != tc.want {
				t.Errorf("chosen %d, want %d", got, tc.want)
			}
			if *restored != 1 {
				t.Errorf("raw mode undone %d times, want 1", *restored)
			}
			s := out.String()
			if !strings.HasPrefix(s, "msg_unknown name=x\r\n\033[?25l") || !strings.HasSuffix(s, "\033[?25h") {
				t.Errorf("output %q: no help first, or the cursor not shown again", s)
			}
			first := max(tc.start, 0)
			if row := "> (*) " + in[first].Name; !strings.Contains(s, row) {
				t.Errorf("output %q: no row %q", s, row)
			}
		})
	}
}

// sections are two headed sections and one without a heading, with fixed
// rows the cursor skips: x (on) and z (off).
func sections() []Section {
	return []Section{
		{Heading: msg.MsgUnknown("top"), Choices: []Choice{{Name: "a", On: true}, {Name: "x", On: true, Fixed: true}, {Name: "b"}}},
		{Heading: msg.MsgUnknown("bottom"), Choices: []Choice{{Name: "z", Fixed: true}, {Name: "c"}}},
		{Choices: []Choice{{Name: "d"}}},
	}
}

func onOfAll(ss []Section) []string {
	var on []string
	for _, s := range ss {
		on = append(on, onOf(s.Choices)...)
	}
	return on
}

func TestPickSectionsKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, keys string
		want       []string
	}{
		{"enter keeps them, the fixed too", "\r", []string{"a", "x"}},
		{"space toggles the first", " \r", []string{"x"}},
		// a, b, c, d: j skips x, and z in the next section.
		{"j skips the fixed rows", "j \r", []string{"a", "x", "b"}},
		{"j twice crosses a heading", "jj \r", []string{"a", "x", "c"}},
		{"down thrice reaches the section without a heading", "\x1b[B\x1b[B\x1b[B \r", []string{"a", "x", "d"}},
		{"up wraps to the last", "k \r", []string{"a", "x", "d"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u, out, _ := testUI(t, tc.keys)
			pickTerminal(u)
			in := sections()
			got := u.Pick(msg.MsgUnknown("x"), in)
			if !slices.Equal(onOfAll(got), tc.want) {
				t.Errorf("chosen %q, want %q", onOfAll(got), tc.want)
			}
			if !slices.Equal(onOfAll(in), []string{"a", "x"}) {
				t.Error("Pick changed its argument")
			}
			s := out.String()
			for _, line := range []string{"msg_unknown name=top\r\n", "msg_unknown name=bottom\r\n", "  [x] x          \r\n", "  [ ] z          \r\n"} {
				if !strings.Contains(s, line) {
					t.Errorf("output %q: no line %q", s, line)
				}
			}
			// Each redraw moves up over the headings too: 2 headings, 6 rows.
			if tc.keys != "\r" && !strings.Contains(s, "\033[8A") {
				t.Errorf("output %q: doesn't move up 8 lines", s)
			}
		})
	}
}

// Fixed rows are greyed out where the output has color.
func TestPickFixedDim(t *testing.T) {
	t.Parallel()
	u, out, _ := testUI(t, "\r")
	pickTerminal(u)
	u.outStyle = style{on: true}
	u.Pick(msg.MsgUnknown("x"), sections())
	if s := out.String(); !strings.Contains(s, "\033["+sgrDim+"m  [x] x") || strings.Contains(s, "\033["+sgrDim+"m> [x] a") {
		t.Errorf("output %q: fixed rows not dim, or a movable one dim", s)
	}
}

// With every row fixed, enter confirms them as they are.
func TestPickAllFixed(t *testing.T) {
	t.Parallel()
	u, _, _ := testUI(t, " j\r")
	pickTerminal(u)
	got := u.Pick(msg.MsgUnknown("x"), []Section{{Choices: []Choice{{Name: "x", On: true, Fixed: true}}}})
	if !slices.Equal(onOfAll(got), []string{"x"}) {
		t.Errorf("chosen %q", onOfAll(got))
	}
}

// CanPick is a terminal both ways, without --no-input.
func TestCanPick(t *testing.T) {
	t.Parallel()
	u, _, _ := testUI(t, "")
	if u.CanPick() {
		t.Error("CanPick without a terminal")
	}
	pickTerminal(u)
	if !u.CanPick() {
		t.Error("not CanPick in a terminal")
	}
	u.SetFlags(Flags{NoInput: true})
	if u.CanPick() {
		t.Error("CanPick with --no-input")
	}
}

// With --no-input the picker isn't shown, even in a terminal: the
// choices stay as given, and nothing is read or refused.
func TestPickNoInput(t *testing.T) {
	t.Parallel()
	u, out, _ := testUI(t, " \r")
	restored := pickTerminal(u)
	u.SetFlags(Flags{NoInput: true})
	got := u.Pick(msg.MsgUnknown("x"), []Section{{Choices: choices()}})[0].Choices
	if !slices.Equal(onOf(got), []string{"a", "b"}) || out.Len() != 0 || *restored != 0 {
		t.Errorf("chosen %q, printed %q, raw mode %d: want the choices as given, nothing printed", onOf(got), out, *restored)
	}
	if line := u.Line(); line != " " {
		t.Errorf("input read: %q left", line)
	}
}

func TestPickOneWithoutTerminal(t *testing.T) {
	t.Parallel()
	u, out, _ := testUI(t, "j\r")
	if got := u.PickOne(msg.MsgUnknown("x"), choices()); got != 0 || out.Len() != 0 {
		t.Errorf("chosen %d, printed %q: want the first on, nothing printed", got, out)
	}
}

func TestPickWithoutTerminal(t *testing.T) {
	t.Parallel()
	u, out, _ := testUI(t, " \r")
	got := u.Pick(msg.MsgUnknown("x"), []Section{{Choices: choices()}})[0].Choices
	if !slices.Equal(onOf(got), []string{"a", "b"}) || out.Len() != 0 {
		t.Errorf("chosen %q, printed %q: want the choices as given, nothing printed", onOf(got), out)
	}
}

func TestPickCtrlC(t *testing.T) {
	t.Parallel()
	u, _, _ := testUI(t, "j\x03 \r")
	restored := pickTerminal(u)
	if code := exitCode(func() { u.Pick(msg.MsgUnknown("x"), []Section{{Choices: choices()}}) }); code != InterruptedCode {
		t.Errorf("exit code %d, want %d", code, InterruptedCode)
	}
	if !u.Interrupted() || *restored != 1 {
		t.Errorf("interrupted %v, raw mode undone %d times", u.Interrupted(), *restored)
	}
}
