package cli

import (
	"context"
	"slices"

	"github.com/spf13/cobra"

	"github.com/devvmhq/devvm/internal/build"
	"github.com/devvmhq/devvm/internal/image"
	"github.com/devvmhq/devvm/internal/msg"
	"github.com/devvmhq/devvm/internal/netpolicy"
	"github.com/devvmhq/devvm/internal/paths"
	"github.com/devvmhq/devvm/internal/ui"
	"github.com/devvmhq/devvm/internal/vm"
)

// upFlags are devvm's flags, all of them for what a new VM gets.
type upFlags struct {
	tools, agents  string // --tools and --agents: lists, or none
	layers         string // --layers: a list, or none
	from           string
	network        string // --network: a tier
	size           vm.Size
	ports          string
	unsafeFolder   bool
	noGitProtect   bool
	clone          bool
	sshAgent       bool
	noDevcontainer bool
	sshConfig      bool
}

// addUpFlags adds devvm's flags to the root command, as its own: no
// subcommand takes them but devvm setup, whose --agents chooses new VMs'
// default, and the commands on this folder's VM, which take --here and
// --parent too (a's).
func addUpFlags(root *cobra.Command, a *app, uf *upFlags) {
	f := root.Flags()
	f.StringVar(&uf.tools, "tools", "", "the `LIST` of toolchains a new VM gets, such as node,python, or none (default: those the folder's files call for)")
	addAgentsFlag(f, &uf.agents, "the `LIST` of coding agents a new VM gets, such as claude,codex, or none (default: devvm setup's)")
	addLayersFlag(f, &uf.layers, "the `LIST` of layers a new VM's image gets, bottom first, such as docker,mine, or none (default: devvm setup's)")
	addFromFlag(f, &uf.from)
	f.StringVar(&uf.network, "network", "", "the network `TIER` a new VM gets: open, internet, allowlist or none, or learn for internet while it learns the hosts it needs (default: devvm network -g's, else allowlist)")
	f.StringVar(&uf.size.CPUs, "cpus", "", "the `N` CPUs the VM gets (default: devvm size -g, else the image's)")
	f.StringVar(&uf.size.Memory, "memory", "", "the VM's memory in `GiB`, such as 16 or 16G (default: devvm size -g, else the image's)")
	f.StringVar(&uf.size.Disk, "disk", "", "the VM's disk in `GiB`, at least the image's (default: devvm size -g, else the image's)")
	f.StringVar(&uf.ports, "ports", "", "the `PORTS` the VM forwards: all, none or a list like 5173,8000-8010 (default: devvm ports -g, else all)")
	f.BoolVar(&uf.clone, "clone", false, "create the VM with its own clone of this repo instead of mounting the folder")
	f.BoolVar(&uf.unsafeFolder, "unsafe-folder", false, "mount a folder devvm refuses, such as your home folder")
	f.BoolVar(&uf.noGitProtect, "no-git-protect", false, "create the VM without .git protection")
	f.BoolVar(&uf.sshAgent, "ssh-agent", false, "create the VM with your SSH agent forwarded, so anything in it can use your keys while you're connected")
	f.BoolVar(&uf.noDevcontainer, "no-devcontainer", false, "create the VM without reading the folder's devcontainer.json")
	addFolderFlags(root, a)
	exclusive(root, "clone", "parent")
	addSSHConfigFlag(f, &uf.sshConfig)
}

// options are what the flags ask of up.
func (uf *upFlags) options() vm.Options {
	tier, learn, _ := netpolicy.Choice(uf.network)
	if uf.network == "" {
		tier = ""
	}
	return vm.Options{
		Toolchains: partFlag(uf.tools), Agents: partFlag(uf.agents), Layers: partFlag(uf.layers),
		Network: tier, Learn: learn, Size: uf.size, Ports: uf.ports,
		From: fromRef(uf.from), FromSet: uf.from != "",
		UnsafeFolder: uf.unsafeFolder, NoGitProtect: uf.noGitProtect, Clone: uf.clone, SSHAgent: uf.sshAgent,
		NoDevcontainer: uf.noDevcontainer,
	}
}

// up opens a shell in this folder's VM, making it first.
func up(ctx context.Context, a *app, uf *upFlags) error {
	o := uf.options()
	defer releaseNotice(ctx, a)()
	return a.env(func(env *vm.Env) error {
		env.AddInclude = uf.sshConfig
		return vm.Launch{Env: env}.Up(ctx, o)
	}, msg.UpFailed)
}

// pickParts returns what shows the tools picker in u's terminal, each
// part under its heading; without one, the rows stay as they are.
func pickParts(u *ui.UI) func(msg.M, []vm.PickPart) []vm.PickPart {
	return func(help msg.M, parts []vm.PickPart) []vm.PickPart {
		sections := make([]ui.Section, len(parts))
		for i, p := range parts {
			sections[i].Heading = p.Heading
			for _, r := range p.Rows {
				sections[i].Choices = append(sections[i].Choices, ui.Choice{Name: r.Name, Desc: u.Text(r.Desc), On: r.On, Fixed: r.Fixed})
			}
		}
		// A list that couldn't show keeps the parts as they were.
		picked, _ := u.Pick(help, sections)
		out := make([]vm.PickPart, len(parts))
		for i, p := range parts {
			out[i] = vm.PickPart{Heading: p.Heading, Rows: slices.Clone(p.Rows)}
			for j := range out[i].Rows {
				out[i].Rows[j].On = picked[i].Choices[j].On
			}
		}
		return out
	}
}

// pickMany is the VM environment's PickMany: the UI's Pick over rows,
// without a heading, with why it couldn't show.
func pickMany(u *ui.UI) func(msg.M, []vm.PickRow) ([]vm.PickRow, error) {
	return func(help msg.M, rows []vm.PickRow) ([]vm.PickRow, error) {
		choices := make([]ui.Choice, len(rows))
		for i, r := range rows {
			choices[i] = ui.Choice{Name: r.Name, Desc: u.Text(r.Desc), On: r.On, Fixed: r.Fixed}
		}
		picked, err := u.Pick(help, []ui.Section{{Choices: choices}})
		out := slices.Clone(rows)
		for i := range out {
			out[i].On = picked[0].Choices[i].On
		}
		return out, err
	}
}

// pickOne is the VM environment's PickOne: the UI's PickOne over rows.
func pickOne(u *ui.UI) func(msg.M, []vm.PickRow) int {
	return func(help msg.M, rows []vm.PickRow) int {
		choices := make([]ui.Choice, len(rows))
		for i, r := range rows {
			choices[i] = ui.Choice{Name: r.Name, Desc: u.Text(r.Desc), On: r.On}
		}
		return u.PickOne(help, choices)
	}
}

// partsNone is the value of --tools, --agents and --layers that chooses
// none of the part.
const partsNone = "none"

// partFlag is a part's flag as up takes it: nil when it's not given, its
// list otherwise, empty for none.
func partFlag(value string) *[]string {
	switch value {
	case "":
		return nil
	case partsNone:
		return &[]string{}
	}
	names := splitList(value)
	return &names
}

// checkPartFlag checks the value of --tools, --agents or --layers (flag,
// as given): none alone, or a comma-separated list of the part's names.
// A name of another part's is refused naming that part's flag, and any
// other with a did-you-mean. The layers are devvm's own and the user's.
func checkPartFlag(flag, value string) error {
	names := splitList(value)
	if slices.Contains(names, partsNone) && len(names) > 1 || len(names) == 0 {
		return msg.PartNoneAlone(flag)
	}
	if value == partsNone {
		return nil
	}
	parts := partNames()
	for _, n := range names {
		if slices.Contains(parts[flag], n) {
			continue
		}
		if other := partFlagOf(parts, n); other != "" {
			return msg.PartOtherFlag(flag, n, other)
		}
	}
	return vm.CheckPart(flag, names, parts[flag])
}

// partFlags are the flags of a new VM's parts, in the order a command
// line names them.
func partFlags() []string { return []string{"--tools", "--agents", "--layers"} }

// partNames is each part's flag and the names it takes: the shared
// tools' toolchains and agents, and the layers, devvm's own and the
// user's.
func partNames() map[string][]string {
	layers := image.Builtins
	if dirs, err := paths.FromEnv(); err == nil {
		layers = (&build.Env{Dirs: dirs}).Layers()[1:]
	}
	return map[string][]string{"--tools": image.Toolchains, "--agents": image.Agents, "--layers": layers}
}

// partFlagOf is the flag that takes name, or "" when no part has it.
func partFlagOf(parts map[string][]string, name string) string {
	for _, f := range partFlags() {
		if slices.Contains(parts[f], name) {
			return f
		}
	}
	return ""
}
