package netpolicy

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/devvmhq/devvm/internal/backend"
	"github.com/devvmhq/devvm/internal/msg"
)

// Tier is a VM's network tier: what its proxy lets it reach, and whether
// its backend confines it to the proxy. Every tier has the proxy.
type Tier string

// The tiers, lowest to highest.
const (
	// TierOpen reaches whatever this machine reaches, its localhost and
	// the LAN included: its backend's own network, unconfined, with the
	// proxy set in its environment, which applies no rules.
	TierOpen Tier = "open"
	// TierInternet reaches every public host on any port, through its
	// proxy alone: the user's denies apply, and no internal address is
	// reached.
	TierInternet Tier = "internet"
	// TierAllowlist reaches only the hosts its policies allow, through its
	// proxy alone.
	TierAllowlist Tier = "allowlist"
	// TierNone reaches only its agents' hosts, its secrets' and its links,
	// through its proxy alone: of the user's files, only denies apply.
	TierNone Tier = "none"
)

// TierDefault is a new VM's tier unless it's chosen otherwise.
const TierDefault = TierAllowlist

// Tiers are the tiers, lowest to highest.
func Tiers() []Tier { return []Tier{TierOpen, TierInternet, TierAllowlist, TierNone} }

// Desc says in a line what a VM with tier t reaches, as the pickers of a
// new VM's tier and of new VMs' show it: the zero message for no tier.
func (t Tier) Desc() msg.M {
	switch t {
	case TierOpen:
		return msg.NetTierOpen()
	case TierInternet:
		return msg.NetTierInternet()
	case TierAllowlist:
		return msg.NetTierAllowlist()
	case TierNone:
		return msg.NetTierNone()
	}
	return msg.M{}
}

// TierNames are the tiers' names, lowest to highest, as the command line
// takes them.
func TierNames() []string {
	names := make([]string, 0, len(Tiers()))
	for _, t := range Tiers() {
		names = append(names, string(t))
	}
	return names
}

// Learn is the network choice that gives a VM the internet tier while it
// learns the hosts it reaches (Learning), which devvm network lock then
// allows on the allowlist tier. It's no tier of its own: the VM's tier is
// internet, and links' and groups' tier rules judge it so.
const Learn = "learn"

// Choices are the network choices, as --network, devvm network and its
// -g take them, in the order devvm shows them: the tiers, lowest to
// highest, with learn after internet, the tier a VM learns on.
func Choices() []string {
	var out []string
	for _, t := range TierNames() {
		out = append(out, t)
		if t == string(TierInternet) {
			out = append(out, Learn)
		}
	}
	return out
}

// Choice reads a network choice: its tier, and whether the VM learns;
// false for a value that's no choice.
func Choice(s string) (t Tier, learn, ok bool) {
	if s == Learn {
		return TierInternet, true, true
	}
	return Tier(s), false, Tier(s).Valid()
}

// ChoiceDesc says in a line what a VM given the choice s reaches, as the
// pickers show it: the zero message for no choice.
func ChoiceDesc(s string) msg.M {
	if s == Learn {
		return msg.NetChoiceLearn()
	}
	return Tier(s).Desc()
}

// Shown is a VM's tier as devvm ls shows it, and devvm network: listed,
// its tier or unenforced (Listed), with (learning) after internet while
// the VM learns. It's data, not a message.
func Shown(listed string, learning bool) string {
	if learning && listed == string(TierInternet) {
		return listed + " (learning)"
	}
	return listed
}

// Valid reports whether t is one of the tiers.
func (t Tier) Valid() bool { return slices.Contains(Tiers(), t) }

// rank is t's place in Tiers: higher is stricter; -1 for no tier.
func (t Tier) rank() int { return slices.Index(Tiers(), t) }

// AtLeast reports whether t is u or stricter. A tier that isn't one is
// neither, and nothing is at least it.
func (t Tier) AtLeast(u Tier) bool { return t.Valid() && u.Valid() && t.rank() >= u.rank() }

// Confined reports whether a VM on t is confined to its proxy: every tier
// but open.
func (t Tier) Confined() bool { return t != TierOpen }

// Net is the network a VM on t starts with (confinementFor): its proxy's
// alone when it's confined, else its backend's own, with the proxy set in
// its environment.
func (t Tier) Net() backend.Net {
	if t.Confined() {
		return backend.NetProxy
	}
	return backend.NetDirect
}

// UnmarshalJSON reads a tier as a VM's state has it: one of the tiers, or
// "" for none set (Of reads it as TierDefault).
func (t *Tier) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s != "" && !Tier(s).Valid() {
		return fmt.Errorf("no tier %q", s)
	}
	*t = Tier(s)
	return nil
}
