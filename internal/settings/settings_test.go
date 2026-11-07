package settings

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/devvmhq/devvm/internal/msg"
	"github.com/devvmhq/devvm/internal/paths"
	"github.com/devvmhq/devvm/internal/state"
)

func testDirs(t *testing.T) paths.Dirs {
	t.Helper()
	dir := t.TempDir()
	return paths.Dirs{Config: filepath.Join(dir, "config"), Data: filepath.Join(dir, "data")}
}

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fullConfig sets every key config.toml has.
const fullConfig = `# every key
network = "internet"
ports = "5173, 8000-8010"
features = ["fzf", "omb"]
agents = ["codex", "claude"]
layers = ["nix", "docker", "mine"]

[size]
cpus = 6
memory = "16G"
disk = 120.5

[retention]
logs.runs = 30
history.age = "90d"
history.count = 5
tools.unused-age = "30d"
orphans.age = "2w"
nix-cache.size = "20G"

[proxy]
https = "http://alice@proxy.corp.example:3128"
http = "proxy.corp.example:3128"
no-proxy = "localhost,.corp.example"
`

// Every key of config.toml is read, checked and in effect, from
// config.toml; with no files each default is devvm's built-in.
func TestReadConfig(t *testing.T) {
	d := testDirs(t)
	def, err := Read(d)
	if err != nil {
		t.Fatal(err)
	}
	want := Defaults{
		Network: Value{"allowlist", FromBuiltin}, Ports: Value{"all", FromBuiltin},
		CPUs: Value{"", FromBuiltin}, Memory: Value{"", FromBuiltin}, Disk: Value{"", FromBuiltin},
		Features: List{Source: FromBuiltin}, Agents: List{Source: FromBuiltin}, Layers: List{Source: FromBuiltin},
		Retention: Retention{Raw: map[string]string{}, Sources: map[string]Source{}},
	}
	if !reflect.DeepEqual(def, want) {
		t.Errorf("no files:\n%+v\nwant\n%+v", def, want)
	}
	write(t, d.ConfigFile(), fullConfig)
	if def, err = Read(d); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		key string
		got Value
		v   string
	}{
		{KeyNetwork, def.Network, "internet"},
		{KeyPorts, def.Ports, "5173,8000-8010"},
		{KeyCPUs, def.CPUs, "6"},
		{KeyMemory, def.Memory, "16"},
		{KeyDisk, def.Disk, "120.5"},
	} {
		if c.got != (Value{c.v, FromConfig}) || def.Source(c.key) != FromConfig {
			t.Errorf("%s = %+v, want %s from config.toml", c.key, c.got, c.v)
		}
	}
	if !slices.Equal(def.Features.Names, []string{"fzf", "omb"}) || !def.Features.Chosen || def.Features.Source != FromConfig {
		t.Errorf("features = %+v", def.Features)
	}
	if !slices.Equal(def.Agents.Names, []string{"codex", "claude"}) || def.Source(KeyAgents) != FromConfig {
		t.Errorf("agents = %+v", def.Agents)
	}
	// Layers keep their order, bottom first: whether each exists is new
	// VMs' to check.
	if !slices.Equal(def.Layers.Names, []string{"nix", "docker", "mine"}) || !def.Layers.Chosen || def.Source(KeyLayers) != FromConfig {
		t.Errorf("layers = %+v", def.Layers)
	}
	r := def.Retention
	if r.RunLogs != 30 || r.ExportsAge != 90*24*time.Hour || r.ExportsCount != 5 || r.ToolsAge != 30*24*time.Hour ||
		r.OrphansAge != 14*24*time.Hour || r.NixCacheCap() != 20<<30 {
		t.Errorf("retention = %+v", r)
	}
	for _, k := range RetentionKeys() {
		if def.Source(KeyRetention+"."+k) != FromConfig || r.Raw[k] == "" {
			t.Errorf("retention %s: %q from %s", k, r.Raw[k], r.Source(k))
		}
	}
	// An empty file sets nothing; so do comments alone.
	for _, empty := range []string{"", "# nothing yet\n", "[size]\n[retention]\n"} {
		write(t, d.ConfigFile(), empty)
		if def, err := Read(d); err != nil || !reflect.DeepEqual(def, want) {
			t.Errorf("%q: %+v, %v", empty, def, err)
		}
	}
}

// An unknown key, a bad value or bad TOML names config.toml and the line;
// nothing of the file is used.
func TestConfigRefused(t *testing.T) {
	d := testDirs(t)
	for _, tc := range []struct {
		name, file string
		line       int
		reason     string
	}{
		{"unknown key", "network = \"none\"\nbackend = \"lima\"\n", 2, `unknown key "backend"`},
		{"unknown table", "[sizes]\ncpus = 2\n", 1, `unknown key "sizes"`},
		{"unknown key in a table", "[size]\ncpus = 2\nswap = 1\n", 3, `unknown key "size.swap"`},
		{"unknown retention key", "[retention]\nlogs.network = 3\n", 2, `unknown key "retention.logs.network"`},
		{"dotted unknown key", "size.swap = 1\n", 1, `unknown key "size.swap"`},
		{"bad network", "network = \"maybe\"\n", 1, `"maybe" isn't one of open, internet, allowlist, none`},
		{"network on", "network = \"on\"\n", 1, `"on" isn't one of open, internet, allowlist, none`},
		{"network ask", "network = \"ask\"\n", 1, `"ask" isn't one of open, internet, allowlist, none`},
		{"network learn", "network = \"learn\"\n", 1, `"learn" isn't one of open, internet, allowlist, none`},
		{"bad ports", "\nports = \"5173,,80\"\n", 2, "port_invalid"},
		{"bad cpus", "[size]\ncpus = 1.5\n", 2, "cpus_not_number flag=cpus"},
		{"bad memory", "[size]\nmemory = \"16M\"\n", 2, "size_not_gib flag=memory"},
		{"bad disk", "[size]\ndisk = true\n", 2, "not a string"},
		{"a feature twice", "features = [\"fzf\", \"fzf\"]\n", 1, `"fzf" is listed twice`},
		{"a bad feature", "features = [\"Fzf\"]\n", 1, "not a feature's name"},
		{"features not a list", "features = \"fzf\"\n", 1, "not a list of names"},
		{"not an agent", "agents = [\"python\"]\n", 1, `"python" isn't a coding agent`},
		{"a layer twice", "layers = [\"nix\", \"nix\"]\n", 1, `"nix" is listed twice`},
		{"base as a layer", "layers = [\"base\"]\n", 1, `not a layer's name: "base"`},
		{"a tool as a layer", "layers = [\"node\"]\n", 1, `not a layer's name: "node"`},
		{"a bad layer", "layers = [\"Mine\"]\n", 1, `not a layer's name: "Mine"`},
		{"layers not a list", "layers = \"nix\"\n", 1, "not a list of names"},
		{"bad count", "[retention]\nhistory.count = 0\n", 2, "a count is a whole number"},
		{"bad age", "[retention]\nhistory.age = \"30\"\n", 2, "bad_duration"},
		{"bad size", "[retention]\nnix-cache.size = \"20g\"\n", 2, "a size is a whole number"},
		{"a proxy's password", "[proxy]\nhttps = \"http://alice:pa55@proxy.corp:3128\"\n", 2, "proxy_password_in_config key=proxy.https"},
		{"an empty proxy password", "[proxy]\nhttp = \"http://alice:@proxy.corp:3128\"\n", 2, "proxy_password_in_config key=proxy.http"},
		{"a socks proxy", "[proxy]\nhttp = \"socks5://proxy.corp:1080\"\n", 2, "upstream_proxy_scheme scheme=socks5:// setting=proxy.http"},
		{"a bad proxy", "[proxy]\nhttps = \"http://proxy.corp:x\"\n", 2, "upstream_proxy_invalid setting=proxy.https"},
		{"a proxy not a string", "[proxy]\nhttps = 3128\n", 2, "not a string"},
		{"a bad no-proxy", "[proxy]\nno-proxy = \"a\\nb\"\n", 2, "upstream_proxy_invalid setting=proxy.no-proxy"},
		{"an unknown proxy key", "[proxy]\nall = \"proxy.corp:1080\"\n", 2, `unknown key "proxy.all"`},
		{"bad TOML", "network = on\n", 1, ""},
		{"a key twice", "network = \"none\"\nnetwork = \"open\"\n", 2, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(t, d.ConfigFile(), tc.file)
			_, err := Read(d)
			c, ok := errors.AsType[*state.CorruptError](err)
			if !ok || c.Path != d.ConfigFile() || c.Line != tc.line || !strings.Contains(c.Shown(msg.M.Names), tc.reason) {
				t.Errorf("got %v, want %s:%d: %s", err, d.ConfigFile(), tc.line, tc.reason)
			}
			// A proxy's password is never shown.
			if ok && (strings.Contains(c.Shown(msg.M.Names), "pa55") || strings.Contains(err.Error(), "pa55")) {
				t.Errorf("the error shows the password: %v", err)
			}
		})
	}
}

// settings.json holds what devvm's commands save, below config.toml's:
// each key is config.toml's where it sets one, else settings.json's.
func TestPrecedence(t *testing.T) {
	d := testDirs(t)
	saved := Values{
		Network: Of("allowlist"), Ports: Of("none"),
		Size: SizeValues{CPUs: Of("2"), Memory: Of("4"), Disk: Of("50")}, Features: Of([]string{}), Agents: Of([]string{"codex"}),
		Layers:    Of([]string{"nix", "docker"}),
		Retention: map[string]string{RetainHistoryAge: "1d", RetainRunLogs: "3"},
	}
	if _, err := Save(d, saved); err != nil {
		t.Fatal(err)
	}
	write(t, d.ConfigFile(), "network = \"open\"\n[size]\nmemory = 8\n[retention]\nhistory.age = \"2d\"\n")
	def, err := Read(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		got  Value
		want Value
	}{
		{def.Network, Value{"open", FromConfig}},
		{def.Ports, Value{"none", FromSettings}},
		{def.CPUs, Value{"2", FromSettings}},
		{def.Memory, Value{"8", FromConfig}},
		{def.Disk, Value{"50", FromSettings}},
	} {
		if c.got != c.want {
			t.Errorf("got %+v, want %+v", c.got, c.want)
		}
	}
	if !def.Features.Chosen || len(def.Features.Names) != 0 || def.Features.Source != FromSettings {
		t.Errorf("features = %+v", def.Features)
	}
	if !slices.Equal(def.Layers.Names, []string{"nix", "docker"}) || def.Layers.Source != FromSettings {
		t.Errorf("layers = %+v", def.Layers)
	}
	if def.Retention.Raw[RetainHistoryAge] != "2d" || def.Retention.Source(RetainHistoryAge) != FromConfig ||
		def.Retention.Source(RetainRunLogs) != FromSettings || def.Retention.Source(RetainOrphansAge) != FromBuiltin {
		t.Errorf("retention = %+v", def.Retention)
	}
}

// Save refuses a key config.toml sets, naming it, and a value devvm can't
// use, before writing anything; it keeps what a change leaves, and a
// retention key set to "" is turned off.
func TestSave(t *testing.T) {
	d := testDirs(t)
	write(t, d.ConfigFile(), "ports = \"none\"\n[retention]\nhistory.age = \"2d\"\n")
	for _, tc := range []struct {
		change Values
		want   string
	}{
		{Values{Ports: Of("all")}, "set_in_config file=" + d.ConfigFile() + " key=ports"},
		{Values{Retention: map[string]string{RetainHistoryAge: ""}}, "set_in_config file=" + d.ConfigFile() + " key=retention.history.age"},
		{Values{Network: Of("maybe")}, ""},
		{Values{Size: SizeValues{CPUs: Of("x")}}, "cpus_not_number flag=cpus value=\"x\""},
	} {
		if _, err := Save(d, tc.change); err == nil || tc.want != "" && msg.NamesOf(err) != tc.want {
			t.Errorf("Save(%+v) = %v, want %s", tc.change, msg.NamesOf(err), tc.want)
		}
	}
	if _, err := os.Stat(d.Settings()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused change wrote settings.json: %v", err)
	}
	if _, err := Save(d, Values{Network: Of("allowlist"), Retention: map[string]string{RetainRunLogs: "5", RetainOrphansAge: "1d"}}); err != nil {
		t.Fatal(err)
	}
	def, err := Save(d, Values{Size: SizeValues{CPUs: Of("3")}, Retention: map[string]string{RetainRunLogs: ""}})
	if err != nil {
		t.Fatal(err)
	}
	if def.Network.Value != "allowlist" || def.CPUs.Value != "3" || def.Retention.RunLogs != 0 || def.Retention.OrphansAge != 24*time.Hour {
		t.Errorf("after two saves: %+v", def)
	}
	data, err := os.ReadFile(d.Settings())
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"network\": \"allowlist\",\n  \"size\": {\n    \"cpus\": \"3\"\n  },\n  \"retention\": {\n    \"orphans.age\": \"1d\"\n  }\n}\n"
	if string(data) != want {
		t.Errorf("settings.json:\n%s\nwant\n%s", data, want)
	}
	if fi, err := os.Stat(d.Settings()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("settings.json's mode: %v, %v", fi, err)
	}
}

// settings.json ignores fields devvm doesn't know, and refuses, naming
// the file and the field, a value devvm can't use.
func TestReadSaved(t *testing.T) {
	d := testDirs(t)
	write(t, d.Settings(), `{"network": "none", "later": {"x": 1}, "retention": {"logs.later": "1", "logs.runs": "4"}}`)
	def, err := Read(d)
	if err != nil || def.Network != (Value{"none", FromSettings}) || def.Retention.RunLogs != 4 {
		t.Errorf("unknown fields: %+v, %v", def, err)
	}
	for data, reason := range map[string]string{
		`{"network": "maybe"}`:              "network: ",
		`{"network": "ask"}`:                "network: ",
		`{"agents": ["claude", "claude"]}`:  "agents: ",
		`{"layers": ["base"]}`:              "layers: ",
		`{"retention": {"logs.runs": "0"}}`: "retention.logs.runs: ",
		`{"ports": 5173}`:                   "cannot unmarshal",
		`not json`:                          "invalid character",
	} {
		write(t, d.Settings(), data)
		_, err := Read(d)
		if c, ok := errors.AsType[*state.CorruptError](err); !ok || c.Path != d.Settings() || !strings.Contains(c.Reason, reason) {
			t.Errorf("%s: got %v, want %q", data, err, reason)
		}
	}
}

// Each source's label names config.toml by its path, and devvm's own by
// name.
func TestLabels(t *testing.T) {
	d := paths.Dirs{Config: "/c", Data: "/d"}
	for s, want := range map[Source]string{
		FromConfig: "/c/config.toml", FromSettings: "devvm: settings.json", FromBuiltin: "devvm: default",
	} {
		if got := s.Label(d); got != want {
			t.Errorf("%s: %q, want %q", s, got, want)
		}
	}
}

func TestKeyLine(t *testing.T) {
	data := "a = 1\n# b = 2\n[size]\n cpus = 2\n\"swap\" = 3\n[ retention ]\nlogs . runs = 1\n"
	for key, want := range map[string]int{"a": 1, "b": 0, "size": 3, "size.cpus": 4, "size.swap": 5, "retention.logs.runs": 7, "x": 0} {
		if got := keyLine(data, key); got != want {
			t.Errorf("keyLine(%q) = %d, want %d", key, got, want)
		}
	}
}
