package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/devvmhq/devvm/assets"
	"github.com/devvmhq/devvm/internal/build"
	"github.com/devvmhq/devvm/internal/msg"
	"github.com/devvmhq/devvm/internal/netpolicy"
	"github.com/devvmhq/devvm/internal/paths"
	"github.com/devvmhq/devvm/internal/settings"
	"github.com/devvmhq/devvm/internal/state"
	"github.com/devvmhq/devvm/internal/ui"
	"github.com/devvmhq/devvm/internal/vm"
)

// featuresNone is the value of devvm setup --features that chooses no
// features.
const featuresNone = "none"

// newSetupCmd is devvm setup [--features LIST|none] [--agents LIST|none]
// [--layers LIST|none]. Its --agents and --layers choose new VMs'
// defaults.
func newSetupCmd(a *app) *cobra.Command {
	var (
		features, agents, layers string
		c                        setupChoice
	)
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Choose base's features, and new VMs' size, network tier, coding agents and layers",
		Long: "Choose the features base gets, and new VMs' CPUs, memory, network tier, coding agents and layers. " +
			"In a terminal devvm asks for each, starting from the current choice, and --features, --agents and --layers choose without asking. " +
			"A new choice of features rebuilds base and the images on it when they're next used, and VMs you already have keep their agents and layers.",
		Example: examples(
			"devvm setup", "answer every question", "devvm setup --features omb,fzf", "give base oh-my-bash and fzf, without asking",
			"devvm setup --features none", "give base no features",
			"devvm setup --agents claude,codex", "give new VMs Claude Code and Codex, without asking",
			"devvm setup --layers docker", "give new VMs the docker layer, without asking",
		),
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Flags().Changed("features") {
				c.features = &features
			}
			if cmd.Flags().Changed("agents") {
				c.agents = partFlag(agents)
			}
			if cmd.Flags().Changed("layers") {
				c.layers = partFlag(layers)
			}
			return failed(newSetup(a).run(c), msg.SetupFailed)
		},
	}
	f := cmd.Flags()
	f.StringVar(&features, "features", "", "the `LIST` of features base gets, such as fzf,omb, or none")
	addAgentsFlag(f, &agents, "the `LIST` of coding agents new VMs get by default, such as claude,codex, or none")
	addLayersFlag(f, &layers, "the `LIST` of layers new VMs' images get by default, bottom first, such as docker,mine, or none")
	return cmd
}

// setupChoice is what devvm setup's flags choose: base's features and new
// VMs' agents and layers (nil for none given).
type setupChoice struct {
	features       *string
	agents, layers *[]string
}

// none reports whether no flag chose anything.
func (c setupChoice) none() bool {
	return c.features == nil && c.agents == nil && c.layers == nil
}

// setup is devvm setup's run: the UI it prints through, devvm's folders,
// whether its pickers are shown, the Reporter it asks for the size through
// (the run's UI; tests make their own), how it asks for the network
// policy and the agents, and the host the size is checked against.
type setup struct {
	ui      *ui.UI
	dirs    func() (paths.Dirs, error)
	canPick func() bool
	pickOne func(msg.M, []ui.Choice) int
	pick    func(msg.M, []vm.PickPart) []vm.PickPart
	sizer   msg.Reporter
	host    func() (vm.Host, error)
}

// newSetup returns a setup on the run's folders, its UI's pickers and
// prompts, on this machine.
func newSetup(a *app) setup {
	u := a.u
	return setup{
		ui:      u,
		dirs:    a.dirs,
		canPick: u.CanPick,
		pickOne: u.PickOne,
		pick:    pickParts(u),
		sizer:   u,
		host:    func() (vm.Host, error) { return vm.ThisHost(a.host()) },
	}
}

// run saves what c chooses: base's features, then new VMs' agents and
// layers. With nothing chosen, it asks for those where its pickers are
// shown (CanPick: what it saves is what they return), with new VMs' size
// and network tier before the agents; otherwise it keeps the features
// (every one until they're chosen) and saves them. A change
// to the features says base rebuilds, and that devvm gc deletes the old
// images. What config.toml sets isn't asked for, said, and a flag
// choosing it is refused (set_in_config).
func (s setup) run(c setupChoice) error {
	dirs, err := s.dirs()
	if err != nil {
		return err
	}
	def, err := settings.Read(dirs)
	if err != nil {
		return err
	}
	ask := c.none() && s.canPick()
	if c.features != nil || c.none() {
		if err := s.saveFeatures(dirs, def, c.features); err != nil {
			return err
		}
	}
	agents := vm.AgentsChoice{Dirs: dirs, Pick: s.pick, Reporter: s.ui}
	layers := vm.LayersChoice{Dirs: dirs, Layers: (&build.Env{Dirs: dirs}).Layers()[1:], Pick: s.pick, Reporter: s.ui}
	if c.agents != nil {
		if err := agents.Set(*c.agents); err != nil {
			return err
		}
	}
	if c.layers != nil {
		return layers.Set(*c.layers)
	}
	if !ask {
		return nil
	}
	host, err := s.host()
	if err != nil {
		return err
	}
	sc := vm.SizeChoice{Dirs: dirs, Host: host, Reporter: s.sizer}
	if err := sc.Ask(); err != nil {
		return err
	}
	if err := s.saveNetwork(dirs); err != nil {
		return err
	}
	if err := agents.Ask(); err != nil {
		return err
	}
	return layers.Ask()
}

// inConfig reports whether config.toml sets key, saying devvm setup
// doesn't ask for it when it does.
func (s setup) inConfig(dirs paths.Dirs, def settings.Defaults, key string) bool {
	if def.Source(key) != settings.FromConfig {
		return false
	}
	s.ui.Info(msg.SetupInConfig(dirs.ConfigFile(), key))
	return true
}

// saveNetwork asks which network tier new VMs get, starting from
// the one in effect, and saves it (vm.NetworkChoice), unless config.toml
// sets it.
func (s setup) saveNetwork(dirs paths.Dirs) error {
	def, err := settings.Read(dirs)
	if err != nil || s.inConfig(dirs, def, settings.KeyNetwork) {
		return err
	}
	modes := settings.NetworkChoices()
	choices := make([]ui.Choice, len(modes))
	for i, m := range modes {
		choices[i] = ui.Choice{Name: m, Desc: s.ui.Text(netpolicy.ChoiceDesc(m)), On: m == def.Network.Value}
	}
	mode := modes[s.pickOne(msg.NetworkDefaultHelp(), choices)]
	return vm.NetworkChoice{Dirs: dirs, Reporter: s.ui}.Set(mode)
}

// saveFeatures saves base's features: features' list, or asked for when
// nil, unless config.toml sets them.
func (s setup) saveFeatures(dirs paths.Dirs, def settings.Defaults, features *string) error {
	if features == nil && s.inConfig(dirs, def, settings.KeyFeatures) {
		return nil
	}
	// Choosing base's features reads devvm's folders and files and asks:
	// no backend builds anything.
	b := build.Choice{Env: &build.Env{Dirs: dirs, Assets: assets.FS, Reporter: s.ui, Pick: pickFeatures(s.ui)}}
	var changed bool
	var err error
	switch {
	case features == nil:
		changed, err = b.PickFeatures()
	case *features == featuresNone:
		changed, err = b.SetFeatures(nil)
	default:
		changed, err = b.SetFeatures(splitList(*features))
	}
	if err != nil || !changed {
		return err
	}
	s.ui.Info(msg.BaseWillRebuild())
	if built, err := state.AnyImage(dirs); err != nil {
		return err
	} else if built {
		s.ui.Say(msg.GCOldHint())
	}
	return nil
}

// splitList splits a comma-separated list, dropping empty items.
func splitList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
