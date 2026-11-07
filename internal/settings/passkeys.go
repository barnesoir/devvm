package settings

import (
	"regexp"

	"github.com/devvmhq/devvm/internal/paths"
)

// passKeys is config.toml's [pass-keys] table: the providers, per agent,
// whose API keys a VM gets as they are, the ones the VM's proxy can't put
// in, such as a local model server's, which devvm otherwise withholds. It
// has an agent's name for each key; pi's is the one so far.
type passKeys struct {
	Pi list[providerKind] `toml:"pi"`
}

// PassKeys returns the providers whose API keys config.toml's
// [pass-keys] says the agent's VMs get as they are, nil for an agent
// it has no key for. No command saves it.
func PassKeys(d paths.Dirs, agent string) ([]string, error) {
	cf, err := decodeConfig(d.ConfigFile())
	if err != nil {
		return nil, err
	}
	if agent == "pi" {
		return cf.PassKeys.Pi.v, nil
	}
	return nil, nil
}

// providerName is a provider's ID, as an agent's login file names it:
// lower case letters, digits, dots, dashes and underscores.
var providerName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

type providerKind struct{}

func (providerKind) parse(v any) (string, error) {
	return checked(text(v))(func(s string) error {
		if !providerName.MatchString(s) {
			return errText("not a provider's ID, such as \"ollama\": " + s)
		}
		return nil
	})
}
