package settings

import (
	"errors"
	"slices"
	"testing"

	"github.com/devvmhq/devvm/internal/state"
)

// config.toml's [pass-keys]: pi's list of providers, none without it, and
// none for an agent it has no key for; a name that isn't a provider's ID,
// a repeat or an agent devvm has no key for is refused, naming its line.
func TestPassKeys(t *testing.T) {
	d := testDirs(t)
	for _, c := range []struct {
		config string
		want   []string
	}{
		{"", nil},
		{"[pass-keys]\n", nil},
		{"[pass-keys]\npi = []\n", []string{}},
		{"[pass-keys]\npi = [\"ollama\", \"lm-studio\"]\n", []string{"ollama", "lm-studio"}},
	} {
		write(t, d.ConfigFile(), c.config)
		if got, err := PassKeys(d, "pi"); err != nil || !slices.Equal(got, c.want) || (got == nil) != (c.want == nil) {
			t.Errorf("%q: %q, %v; want %q", c.config, got, err, c.want)
		}
		if got, err := PassKeys(d, "opencode"); err != nil || got != nil {
			t.Errorf("%q for opencode: %q, %v", c.config, got, err)
		}
	}
	for config, line := range map[string]int{
		"[pass-keys]\npi = [\"Ollama\"]\n":            2,
		"[pass-keys]\npi = [\"a\", \"a\"]\n":          2,
		"[pass-keys]\npi = \"ollama\"\n":              2,
		"# x\n[pass-keys]\nopencode = [\"ollama\"]\n": 3,
	} {
		write(t, d.ConfigFile(), config)
		_, err := PassKeys(d, "pi")
		if c, ok := errors.AsType[*state.CorruptError](err); !ok || c.Line != line {
			t.Errorf("%q: %v, want line %d", config, err, line)
		}
	}
}
