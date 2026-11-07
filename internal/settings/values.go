package settings

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/devvmhq/devvm/internal/backend"
	"github.com/devvmhq/devvm/internal/msg"
)

var (
	wholeNumber = regexp.MustCompile(`^[1-9][0-9]*$`)
	gibNumber   = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
)

// ParseCPUs checks a CPU count, as flag (--cpus, or config.toml's cpus)
// gives it.
func ParseCPUs(flag, v string) (string, error) {
	if !wholeNumber.MatchString(v) {
		return "", msg.CpusNotNumber(flag, strconv.Quote(v))
	}
	return v, nil
}

// ParseGiB checks a size in GiB, as flag (--memory, --disk, or
// config.toml's memory or disk) gives it: N, NG or NGiB, decimals
// allowed. It returns N.
func ParseGiB(flag, v string) (string, error) {
	n := strings.TrimSuffix(v, "iB")
	n = strings.TrimSuffix(strings.TrimSuffix(n, "G"), "g")
	if !gibNumber.MatchString(n) || !strings.ContainsAny(n, "123456789") {
		return "", msg.SizeNotGib(flag, strconv.Quote(v))
	}
	return n, nil
}

// Ports values: every port the VM listens on is forwarded, or none.
const (
	PortsAll  = "all"
	PortsNone = "none"
)

// ParsePorts checks which ports to forward, as --ports, config.toml or
// settings.json give them: all, none, or ports and ranges
// (5173,8000-8010, backend.ParsePortRanges). It returns the value without
// spaces or repeats.
func ParsePorts(v string) (string, error) {
	if s := strings.ReplaceAll(v, " ", ""); s == PortsAll || s == PortsNone {
		return s, nil
	}
	rs, err := backend.ParsePortRanges(v)
	if err != nil {
		return "", msg.PortInvalid(strconv.Quote(v)).Because(err)
	}
	return backend.FormatPortRanges(rs), nil
}

// NetworkDefault is new VMs' network tier unless one is set:
// netpolicy.TierDefault, which netpolicy's tests check it matches.
const NetworkDefault = "allowlist"

// NetworkChoices are the network defaults, the tiers, in the order devvm
// shows them, lowest to highest. They are netpolicy's (netpolicy.Tiers,
// which imports this package), and netpolicy's tests check the two lists
// match. Learning the hosts a VM needs is no default: each VM is made to
// learn on its own.
func NetworkChoices() []string {
	return []string{"open", "internet", NetworkDefault, "none"}
}

// checkNetwork refuses a network default that isn't a tier.
func checkNetwork(v string) error {
	if !slices.Contains(NetworkChoices(), v) {
		return errNotChoice(v, NetworkChoices())
	}
	return nil
}
