package agentlogin

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/devvmhq/devvm/internal/agents"
)

// The login kinds, as the tests name them.
const (
	Codex       = agents.Codex
	Cursor      = agents.Cursor
	Opencode    = agents.Opencode
	Claude      = agents.Claude
	Pi          = agents.Pi
	ClaudeOAuth = agents.ClaudeOAuth
)

// canary is the value planted where no format knows a field (plantCanaries).
const canary = "devvm-canary-e2efake"

// plantCanaries adds to v, and to every object in it, a field no format knows, holding canary as
// a string, in an object and in a list.
func plantCanaries(v any) {
	switch t := v.(type) {
	case map[string]any:
		for _, x := range t {
			plantCanaries(x)
		}
		t["zz_canary"] = canary
		t["zz_canary_object"] = map[string]any{"zz_canary": canary}
		t["zz_canary_list"] = []any{canary, map[string]any{"zz_canary": canary}}
	case []any:
		for _, x := range t {
			plantCanaries(x)
		}
	}
}

// Every format's VM copy holds only the fields it knows: a field it doesn't, at the top, in an
// object or in a list, at any depth, never reaches the VM. A new format is checked as its golden
// login is added (goldenLogins).
func TestFormatsWithholdUnknown(t *testing.T) {
	logins := goldenLogins()
	for kind := range formats() {
		t.Run(kind, func(t *testing.T) {
			data, ok := logins[kind]
			if !ok {
				t.Fatalf("no golden login for %s in goldenLogins", kind)
			}
			var m map[string]any
			must(t, json.Unmarshal([]byte(data), &m))
			plantCanaries(m)
			b, err := json.Marshal(m)
			must(t, err)
			f := File{Kind: kind, Path: filepath.Join(t.TempDir(), "auth.json"), Salt: "s4lt"}
			must(t, os.WriteFile(f.Path, b, 0o600))
			c, err := f.VMCopy()
			must(t, err)
			if strings.Contains(string(c.Data), canary) {
				t.Errorf("the VM's copy holds a field devvm doesn't know:\n%s", c.Data)
			}
		})
	}
}

// Every agent's login file has a format, and every format is an agent's login file's: one
// with API keys (agents.Keys) can save them, and none can that has none to save.
func TestFormatsCoverLogins(t *testing.T) {
	kinds := agents.LoginKinds()
	if got := slices.Sorted(maps.Keys(formats())); !slices.Equal(got, slices.Sorted(slices.Values(kinds))) {
		t.Errorf("formats are for %v, the agents' login files are %v", got, kinds)
	}
	for _, d := range agents.Defs {
		_, keys := formats()[d.Name].(keyFormat)
		if keys != (d.Keys != agents.NoKeys) {
			t.Errorf("%s: its login's format saves API keys: %v; its Keys: %v", d.Name, keys, d.Keys)
		}
		if len(d.Logins) > 0 && d.Logins[0].Kind != d.Name {
			t.Errorf("%s: its first login file is of kind %s, not its name's", d.Name, d.Logins[0].Kind)
		}
		_, chatGPT := formats()[d.Name].(chatGPTFormat)
		if chatGPT != d.ChatGPT {
			t.Errorf("%s: its login's format holds a ChatGPT login: %v; its ChatGPT: %v", d.Name, chatGPT, d.ChatGPT)
		}
	}
}
