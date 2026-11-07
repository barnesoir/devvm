package agentlogin

import (
	"slices"
	"strings"
	"testing"
)

// pi's auth.json: the API keys of Anthropic, OpenAI and OpenRouter become the VM's placeholders,
// bound for their hosts and headers, and Get reads them from the host's file; a command key and
// another provider's key stay as they are, named; an OAuth login loses its tokens and whatever
// else looks like a secret, named too; what isn't a secret stays.
func TestPiLogins(t *testing.T) {
	f := File{Kind: Pi, Salt: "s1", Path: writeFile(t, map[string]any{
		"anthropic":    map[string]any{"type": "api_key", "key": "sk-ant-e2efake"},
		"openrouter":   map[string]any{"type": "api_key", "key": "sk-or-e2efake", "env": map[string]any{"X": "kept"}},
		"openai":       map[string]any{"type": "api_key", "key": "!security find-generic-password -ws openai"},
		"groq":         map[string]any{"type": "api_key", "key": "gsk-local"},
		"openai-codex": map[string]any{"type": "oauth", "access": "at-e2efake", "refresh": "rt-e2efake", "expires": 1, "accountId": "acct-1", "idToken": "id-e2efake"}, //nolint:gosec // G101: fake tokens, which no service takes
	})}
	bs := bindings(t, f)
	var got []string
	for _, b := range bs {
		got = append(got, b.Name+" "+strings.Join(b.Hosts, ",")+" "+b.Header+" "+b.Placeholder)
	}
	want := []string{
		"pi-anthropic api.anthropic.com x-api-key devvm-proxy-managed-pi-anthropic-s1",
		"pi-openrouter openrouter.ai Authorization devvm-proxy-managed-pi-openrouter-s1",
	}
	if !slices.Equal(got, want) {
		t.Errorf("bindings:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	c, err := f.VMCopy()
	must(t, err)
	out := string(c.Data)
	for _, secret := range []string{"sk-ant-e2efake", "sk-or-e2efake", "at-e2efake", "rt-e2efake", "id-e2efake"} {
		if strings.Contains(out, secret) {
			t.Errorf("the VM's copy holds %q:\n%s", secret, out)
		}
	}
	for _, kept := range []string{"devvm-proxy-managed-pi-anthropic-s1", `"kept"`, "!security find-generic-password", "gsk-local", "acct-1", `"api_key"`} {
		if !strings.Contains(out, kept) {
			t.Errorf("the VM's copy lacks %q:\n%s", kept, out)
		}
	}
	if !slices.Equal(c.Kept, []string{"groq", "openai"}) || !slices.Equal(c.Withheld, []string{"openai-codex"}) {
		t.Errorf("kept %v, withheld %v", c.Kept, c.Withheld)
	}
	if v, err := f.Get(t.Context(), "pi-anthropic"); err != nil || v != "sk-ant-e2efake" {
		t.Errorf("Get(pi-anthropic) = %q, %v", v, err)
	}
	for _, name := range []string{"pi-openai", "pi-groq", "pi-openai-codex", "pi-nothing"} {
		if v, err := f.Get(t.Context(), name); err == nil {
			t.Errorf("Get(%s) = %q, no error", name, v)
		}
	}
}

// devvm agent login pi --api-key: pi's entry for the provider in its own format, its env kept, and
// its other providers kept; a provider devvm doesn't put a key in for is refused.
func TestPiSetKey(t *testing.T) {
	if got := KeyProviders(Pi); !slices.Equal(got, []string{"anthropic", "openai", "openrouter"}) {
		t.Errorf("KeyProviders(pi) = %v", got)
	}
	p := storeFile(t, Pi, ".pi/agent/auth.json")
	must(t, p.lockStoreWrite(map[string]any{
		"openai": map[string]any{"type": "api_key", "key": "old", "env": map[string]any{"OPENAI_ORG": "org-1"}},
		"groq":   map[string]any{"type": "api_key", "key": "gsk"},
	}))
	must(t, p.SetKey("openai", "sk-new"))
	must(t, p.SetKey("anthropic", "sk-ant"))
	m := readStore(t, p)
	switch e := obj(m, "openai"); {
	case str(e, "type") != "api_key" || str(e, "key") != "sk-new" || str(obj(e, "env"), "OPENAI_ORG") != "org-1":
		t.Errorf("pi's openai entry: %v", e)
	case str(obj(m, "anthropic"), "key") != "sk-ant" || str(obj(m, "groq"), "key") != "gsk":
		t.Errorf("pi's login: %v", m)
	}
	if err := p.SetKey("groq", "k"); err == nil {
		t.Error("SetKey(pi, groq) took it")
	}
	if bs, _ := p.Bindings(); len(bs) != 2 {
		t.Errorf("pi's bindings: %v", bs)
	}
}
