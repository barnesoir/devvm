package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/devvmhq/devvm/internal/msg"
	"github.com/devvmhq/devvm/internal/paths"
	"github.com/devvmhq/devvm/internal/settings"
	"github.com/devvmhq/devvm/internal/ui"
	"github.com/devvmhq/devvm/internal/vm"
)

// setupSandbox points devvm's folders at a temporary HOME and returns a setup that sees a terminal (or not),
// keeping the size with Enter and picking the none tier, on a host
// of 8 CPUs and 32 GiB; the folders; and the size prompts and pickers
// shown.
func setupSandbox(t *testing.T, terminal bool) (setup, paths.Dirs, *[]string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("DEVVM_LIMA_HOME", "")
	d, err := paths.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	var sized []string
	u, _, _ := testUI()
	s := setup{
		ui:      u,
		dirs:    func() (paths.Dirs, error) { return d, nil },
		canPick: func() bool { return terminal },
		pickOne: func(help msg.M, cs []ui.Choice) int {
			if help.ID() != "network_default_help" {
				t.Errorf("asked %s", help.ID())
			}
			sized = append(sized, pickedNetwork(cs))
			return slices.IndexFunc(cs, func(c ui.Choice) bool { return c.Name == "none" })
		},
		// The agents' question checks Claude Code.
		pick: func(help msg.M, parts []vm.PickPart) []vm.PickPart {
			sized = append(sized, help.ID())
			parts[0].Rows[0].On = true
			return parts
		},
		sizer: &msg.Fake{Terminal: true, OnInfo: u.Info, OnAnswer: func(m msg.M) string { sized = append(sized, m.Names()); return "" }},
		host:  func() (vm.Host, error) { return vm.Host{CPUs: 8, MemoryGiB: 32}, nil },
	}
	return s, d, &sized
}

// defaults reads the defaults in effect in d.
func defaults(t *testing.T, d paths.Dirs) settings.Defaults {
	t.Helper()
	def, err := settings.Read(d)
	if err != nil {
		t.Fatal(err)
	}
	return def
}

// save saves a default as devvm's commands do.
func save(t *testing.T, d paths.Dirs, v settings.Values) {
	t.Helper()
	if _, err := settings.Save(d, v); err != nil {
		t.Fatal(err)
	}
}

// devvm setup --agents sets new VMs' agents without asking, none for
// none; in a terminal without flags, it asks for them last.
func TestSetupAgents(t *testing.T) {
	s, d, asked := setupSandbox(t, true)
	for _, tc := range []struct {
		value string
		want  []string
	}{{"codex,claude", []string{"claude", "codex"}}, {"none", []string{}}} {
		if err := s.run(setupChoice{agents: partFlag(tc.value)}); err != nil {
			t.Fatal(err)
		}
		if got := defaults(t, d).Agents; !got.Chosen || !slices.Equal(got.Names, tc.want) {
			t.Errorf("--agents %s: saved %+v", tc.value, got)
		}
	}
	if len(*asked) > 0 {
		t.Errorf("asked %q", *asked)
	}
	if err := s.run(setupChoice{}); err != nil {
		t.Fatal(err)
	}
	if n := len(*asked); n < 2 || (*asked)[n-2] != "agents_help" {
		t.Errorf("asked %q, want agents_help before layers_help", *asked)
	}
	if got := defaults(t, d).Agents.Names; !slices.Equal(got, []string{"claude"}) {
		t.Errorf("saved %q", got)
	}
}

// devvm setup --layers sets new VMs' layers without asking, bottom first
// as given, none for none, and with --agents sets both; in a terminal
// without flags, it asks for them last, starting from the saved ones
// and keeping their order.
func TestSetupLayers(t *testing.T) {
	s, d, asked := setupSandbox(t, true)
	for _, tc := range []struct {
		c    setupChoice
		want []string
	}{
		{setupChoice{layers: partFlag("nix,docker,nix")}, []string{"nix", "docker"}},
		{setupChoice{layers: partFlag("none")}, []string{}},
		{setupChoice{agents: partFlag("codex"), layers: partFlag("docker")}, []string{"docker"}},
	} {
		if err := s.run(tc.c); err != nil {
			t.Fatal(err)
		}
		if got := defaults(t, d).Layers; !got.Chosen || !slices.Equal(got.Names, tc.want) {
			t.Errorf("%+v: saved %+v", tc.c, got)
		}
	}
	if got := defaults(t, d).Agents.Names; !slices.Equal(got, []string{"codex"}) {
		t.Errorf("--agents with --layers saved agents %q", got)
	}
	if len(*asked) > 0 {
		t.Errorf("asked %q", *asked)
	}
	if err := s.run(setupChoice{}); err != nil {
		t.Fatal(err)
	}
	if n := len(*asked); n == 0 || (*asked)[n-1] != "layers_help" {
		t.Errorf("asked %q, want layers_help last", *asked)
	}
	// The picker checked desktop as well as docker: docker stays at the
	// bottom.
	if got := defaults(t, d).Layers.Names; !slices.Equal(got, []string{"docker", "desktop"}) {
		t.Errorf("saved %q", got)
	}
}

// pickedNetwork is the network picker's choices, as names, the one it
// starts on starred, and their descriptions' message names.
func pickedNetwork(cs []ui.Choice) string {
	s := "network"
	for _, c := range cs {
		on := ""
		if c.On {
			on = "*"
		}
		s += " " + on + c.Name + ":" + c.Desc
	}
	return s
}

// The network picker starts from the network tier saved for new VMs.
func TestSetupNetworkStartsFromSaved(t *testing.T) {
	s, d, picked := setupSandbox(t, true)
	save(t, d, settings.Values{Network: settings.Of("internet")})
	if err := s.run(setupChoice{}); err != nil {
		t.Fatal(err)
	}
	want := "network open:net_tier_open *internet:net_tier_internet " +
		"allowlist:net_tier_allowlist none:net_tier_none"
	if !slices.Contains(*picked, want) {
		t.Errorf("pickers %q, want %q", *picked, want)
	}
	if mode := defaults(t, d).Network; mode != (settings.Value{Value: "none", Source: settings.FromSettings}) {
		t.Errorf("network tier for new VMs %+v", mode)
	}
}

// In a terminal, setup with no flag asks for the features, new VMs' size,
// network policy and agents; --features or no terminal asks none of them.
func TestSetupAsks(t *testing.T) {
	none := ""
	for _, tc := range []struct {
		name     string
		terminal bool
		features *string
		ask      bool
	}{
		{name: "a terminal", terminal: true, ask: true},
		{name: "no terminal"},
		{name: "--features", terminal: true, features: &none},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, d, sized := setupSandbox(t, tc.terminal)
			if err := s.run(setupChoice{features: tc.features}); err != nil {
				t.Fatal(err)
			}
			wantSized := []string(nil)
			if tc.ask {
				wantSized = []string{
					"size_cpus_prompt cpus=4", "size_memory_prompt memory=8",
					"network open:net_tier_open internet:net_tier_internet " +
						"*allowlist:net_tier_allowlist none:net_tier_none",
					"agents_help", "layers_help",
				}
			}
			if !slices.Equal(*sized, wantSized) {
				t.Errorf("size prompts and network pickers %q, want %q", *sized, wantSized)
			}
			def := defaults(t, d)
			if mode := def.Network.Value; mode != map[bool]string{true: "none", false: settings.NetworkDefault}[tc.ask] {
				t.Errorf("network tier for new VMs %q", mode)
			}
			if def.CPUs.Source != settings.FromBuiltin || def.Memory.Source != settings.FromBuiltin {
				t.Errorf("Enter saved a size: %+v %+v", def.CPUs, def.Memory)
			}
			if !def.Features.Chosen {
				t.Error("base's features not chosen")
			}
		})
	}
}

// What config.toml sets, devvm setup doesn't ask for, saying so, and its
// flags can't choose (set_in_config); it still asks for the rest.
func TestSetupConfigSets(t *testing.T) {
	s, d, sized := setupSandbox(t, true)
	u, said, _ := testUI()
	s.ui = u
	s.sizer.(*msg.Fake).OnInfo = u.Info
	config := "network = \"allowlist\"\nfeatures = []\nagents = [\"codex\"]\nlayers = [\"docker\"]\n[size]\ncpus = 2\n"
	if err := os.MkdirAll(d.Config, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.ConfigFile(), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.run(setupChoice{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*sized, []string{"size_memory_prompt memory=8"}) {
		t.Errorf("asked %q", *sized)
	}
	for _, key := range []string{"features", "size.cpus", "network", "agents", "layers"} {
		if want := "setup_in_config file=" + d.ConfigFile() + " key=" + key; !strings.Contains(said.String(), want) {
			t.Errorf("said\n%s\nwant %s", said, want)
		}
	}
	if _, err := os.Stat(d.Settings()); err == nil {
		t.Error("saved settings.json")
	}
	for _, c := range []setupChoice{{features: &[]string{"none"}[0]}, {agents: partFlag("claude")}, {layers: partFlag("nix")}} {
		if err := s.run(c); msg.IDOf(err) != "set_in_config" {
			t.Errorf("%+v: %v", c, msg.NamesOf(err))
		}
	}
}
