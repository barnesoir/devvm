package agents

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// root is the repo's root, from this package's folder.
const root = "../.."

// Every agent has what the rest of devvm finds it by, beside its Def: its
// shared tool's backend in shared-tools/mise.toml's [tool_alias], so
// mise's registry can't move it, and its row in the docs' Supported
// agents table, in the registry's order. (Its policy and its [tools] line
// are every shared tool's, which internal/image's TestSharedToolsPolicies
// and internal/tools' TestConfigTools check, and its login files' formats
// internal/agentlogin's TestFormatsCoverLogins.)
func TestDefsComplete(t *testing.T) {
	var mise struct {
		Alias map[string]string `toml:"tool_alias"`
	}
	if _, err := toml.DecodeFile(filepath.Join(root, "assets", "shared-tools", "mise.toml"), &mise); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, row := range pageTable(t, "## Supported agents") {
		names = append(names, row[0])
	}
	if !slices.Equal(names, Names()) {
		t.Errorf("Supported agents lists %v, the registry %v, in its order", names, Names())
	}
	for _, d := range Defs {
		if mise.Alias[d.Name] == "" {
			t.Errorf("%s: shared-tools/mise.toml's [tool_alias] has no line for it", d.Name)
		}
	}
}

// pageTable is the rows of the table in coding-agents.md's section of
// that heading whose first cell is a name in backticks, each row's cells
// trimmed, the first without its backticks.
func pageTable(t *testing.T, heading string) [][]string {
	t.Helper()
	page, err := os.ReadFile(filepath.Join(root, "docs", "content", "docs", "using", "coding-agents.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(page), "\n"+heading+"\n")
	if !ok {
		t.Fatalf("coding-agents.md has no %q section", heading)
	}
	level, _, _ := strings.Cut(heading, " ")
	section, _, _ = strings.Cut(section, "\n"+level+" ")
	var rows [][]string
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		cells[0] = strings.Trim(cells[0], "`")
		rows = append(rows, cells)
	}
	return rows
}

// The providers are each whole and sorted by ID, and the docs' table of
// them names each, in that order, with its name, its hosts and its header.
func TestProvidersComplete(t *testing.T) {
	code := regexp.MustCompile("`([^`]+)`")
	spans := func(s string) []string {
		var out []string
		for _, m := range code.FindAllStringSubmatch(s, -1) {
			out = append(out, m[1])
		}
		return out
	}
	rows := pageTable(t, "### API keys the proxy puts in")
	if len(rows) != len(Providers) {
		t.Errorf("the docs' table has %d providers, the registry %d", len(rows), len(Providers))
	}
	for i, p := range Providers {
		if p.ID == "" || p.Display == "" || len(p.Hosts) == 0 || p.Header == "" {
			t.Errorf("%+v: no ID, name, hosts or header", p)
		}
		if i > 0 && Providers[i-1].ID >= p.ID {
			t.Errorf("%s: after %s, out of order", p.ID, Providers[i-1].ID)
		}
		if got, ok := ProviderOf(p.ID); !ok || got.ID != p.ID {
			t.Errorf("ProviderOf(%s) = %v, %v", p.ID, got, ok)
		}
		if i >= len(rows) {
			continue
		}
		row := rows[i]
		if len(row) != 4 || row[0] != p.ID || row[1] != p.Display || !slices.Equal(spans(row[2]), p.Hosts) || !slices.Equal(spans(row[3]), []string{p.Header}) {
			t.Errorf("the docs' table's row %v isn't %+v", row, p)
		}
	}
	if ids := ProviderIDs(); len(ids) != len(Providers) || !slices.IsSorted(ids) {
		t.Errorf("ProviderIDs = %v", ids)
	}
	if _, ok := ProviderOf("none"); ok {
		t.Error("ProviderOf finds a provider that isn't one")
	}
}

// Each Def is whole and its own: a name, its folder, logins of kinds no
// other has, the first of its name, history excludes inside its history,
// and settings inside its folder.
func TestDefsWellFormed(t *testing.T) {
	kinds := map[string]bool{}
	for _, d := range Defs {
		if d.Name == "" || d.Display == "" || d.Folder == "" {
			t.Errorf("%+v: no name, display name or folder", d)
		}
		if len(d.Logins) > 0 && d.Logins[0].Kind != d.Name {
			t.Errorf("%s: its first login's kind is %s", d.Name, d.Logins[0].Kind)
		}
		for _, l := range d.Logins {
			if kinds[l.Kind] {
				t.Errorf("%s: login kind %s is another's too", d.Name, l.Kind)
			}
			kinds[l.Kind] = true
			if got, a, ok := LoginOf(l.Kind); !ok || got != l || a.Name != d.Name {
				t.Errorf("LoginOf(%s) = %v, %s, %v", l.Kind, got, a.Name, ok)
			}
		}
		for _, x := range d.HistoryExcludes {
			if !slices.ContainsFunc(d.History, func(h string) bool { return x == h || strings.HasPrefix(x, h+"/") }) {
				t.Errorf("%s: history exclude %s is outside its history %v", d.Name, x, d.History)
			}
		}
		for _, p := range slices.Concat(d.Dirs, filesOf(d)) {
			if !strings.HasPrefix(p, d.Folder+"/") {
				t.Errorf("%s: setting %s is outside its folder %s", d.Name, p, d.Folder)
			}
		}
		if got, ok := Get(d.Name); !ok || got.Name != d.Name {
			t.Errorf("Get(%s) = %v", d.Name, ok)
		}
	}
	if _, ok := Get("none"); ok {
		t.Error("Get finds an agent that isn't one")
	}
	if _, _, ok := LoginOf("none"); ok {
		t.Error("LoginOf finds a login that isn't one")
	}
}

func filesOf(d Def) []string {
	var out []string
	for _, f := range d.Files {
		out = append(out, f.Rel)
	}
	return out
}

// The settings files whose VM copies devvm parses, and those it withholds.
func TestSettingsFormat(t *testing.T) {
	for rel, want := range map[string]Format{
		".claude/settings.json": JSON, ".codex/config.toml": TOML, OpencodeConfig + "/opencode.json": JSON,
		OpencodeConfig + "/tui.jsonc": JSON, OpencodeConfig + "/x.toml": TOML, PiSettings: JSON,
		".claude/CLAUDE.md": AsIs, PiFolder + "/keybindings.json": AsIs, ".claude/other.json": AsIs,
	} {
		if got, ok := SettingsFormat(rel); got != want || ok != (want != AsIs) {
			t.Errorf("SettingsFormat(%s) = %q, %v; want %q", rel, got, ok, want)
		}
	}
	for rel, want := range map[string]bool{
		OpencodeConfig + "/.env": true, OpencodeConfig + "/notes.txt": true, OpencodeConfig + "/AGENTS.md": false,
		OpencodeConfig + "/opencode.json": false, OpencodeConfig + "/plugin/x.env": false, ".codex/x.env": false,
	} {
		if got := Withheld(rel); got != want {
			t.Errorf("Withheld(%s) = %v, want %v", rel, got, want)
		}
	}
}

// The lists of every agent's are each Def's, in Defs' order, and Of,
// which code of one agent's own asks with its constant, finds it.
func TestLists(t *testing.T) {
	var history, excludes, kinds []string
	var env []Env
	for _, d := range Defs {
		history, excludes, env = append(history, d.History...), append(excludes, d.HistoryExcludes...), append(env, d.Env...)
		for _, l := range d.Logins {
			kinds = append(kinds, l.Kind)
		}
	}
	if got := History(); !slices.Equal(got, history) || !slices.Contains(got, ClaudeJSON) {
		t.Errorf("History = %v", got)
	}
	if got := HistoryExcludes(); !slices.Equal(got, excludes) {
		t.Errorf("HistoryExcludes = %v", got)
	}
	if got := GuestEnv(); !slices.Equal(got, env) || !slices.Contains(got, Env{"PI_TELEMETRY", "0"}) {
		t.Errorf("GuestEnv = %v", got)
	}
	if got := LoginKinds(); !slices.Equal(got, kinds) || !slices.Contains(got, ClaudeOAuth) {
		t.Errorf("LoginKinds = %v", got)
	}
	if Of(Pi).Folder != PiFolder {
		t.Error("Of(pi)")
	}
	defer func() {
		if recover() == nil {
			t.Error("Of of no agent didn't panic")
		}
	}()
	Of("none")
}

// The agents devvm agent login logs in, and those it saves keys alone for.
func TestLoginAgents(t *testing.T) {
	if got := LoginAgents(); !slices.Equal(got, Names()) {
		t.Errorf("LoginAgents = %v", got)
	}
	if got := Select(Def.KeysOnly); !slices.Contains(got, Pi) || slices.Contains(got, Claude) || slices.Contains(got, Codex) {
		t.Errorf("KeysOnly agents = %v", got)
	}
}
