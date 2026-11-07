package agentlogin

// pi (checked against upstream at 1.5.0, 2026-11) keeps its logins in ~/.pi/agent/auth.json, one
// entry per provider: {"type":"api_key","key","env"}, where a key that starts with ! is a command
// pi runs for the key, or {"type":"oauth","access","refresh","expires" (ms)} with the provider's
// own fields. devvm binds the API keys of the providers whose hosts it knows (opencodeAPI, the same
// providers as opencode's), and keeps no OAuth login of pi's: the VM's copy holds those without
// their tokens, and pi's other keys as they are.

import (
	"fmt"
	"strings"

	"github.com/devvmhq/devvm/internal/proxy"
)

// piPlaceholder is the VM's in place of a provider's API key in pi's auth.json.
func piPlaceholder(provider, salt string) string {
	return salted("devvm-proxy-managed-pi-"+provider, salt)
}

// piKey returns the API key of pi's entry for provider id in m, and whether devvm binds it: an
// api_key entry of a provider in opencodeAPI whose key is a value, not a command.
func piKey(m map[string]any, id string) (string, bool) {
	e := obj(m, id)
	k := str(e, "key")
	_, known := opencodeAPI[id]
	return k, known && str(e, "type") == "api_key" && k != "" && !strings.HasPrefix(k, "!")
}

func piBindings(m map[string]any, salt string) []proxy.Binding {
	var bs []proxy.Binding
	for _, id := range sortedKeys(m) {
		if _, ok := piKey(m, id); ok {
			p := opencodeAPI[id]
			bs = append(bs, login(Pi, "pi-"+id, p.hosts, p.header, piPlaceholder(id, salt)))
		}
	}
	return bs
}

func piVM(m map[string]any, salt string) map[string]any {
	// An OAuth login loses its tokens, and any other field that looks like a secret's.
	for _, id := range piUnbound(m, true) {
		e := obj(m, id)
		for _, k := range sortedKeys(e) {
			if s := str(e, k); s != "" && (k == "access" || k == "refresh" || redactName.MatchString(k)) {
				e[k] = redactMark
			}
		}
	}
	for _, b := range piBindings(m, salt) {
		obj(m, strings.TrimPrefix(b.Name, "pi-"))["key"] = b.Placeholder
	}
	return m
}

// piUnbound returns the providers of pi's whose logins devvm doesn't bind, sorted: the OAuth ones
// (which the VM's copy holds without their tokens), or the others (which it holds as they are).
func piUnbound(m map[string]any, oauth bool) []string {
	var out []string
	for _, id := range sortedKeys(m) {
		if _, ok := piKey(m, id); !ok && (str(obj(m, id), "type") == "oauth") == oauth {
			out = append(out, id)
		}
	}
	return out
}

func (f File) piGet(name string) (string, error) {
	m, err := readJSON(f.Path)
	if err != nil {
		return "", err
	}
	if k, ok := piKey(m, strings.TrimPrefix(name, "pi-")); ok {
		return k, nil
	}
	return "", fmt.Errorf("no pi API key %q", name)
}
