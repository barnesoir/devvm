package netpolicy

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devvmhq/devvm/assets"
	"github.com/devvmhq/devvm/internal/paths"
	"github.com/devvmhq/devvm/internal/state"
)

// The network choices are the tiers with learn after internet; learn
// reads as the internet tier, learning, and a value that's no choice is
// refused. Each has what it reaches.
func TestChoices(t *testing.T) {
	if got := strings.Join(Choices(), " "); got != "open internet learn allowlist none" {
		t.Errorf("Choices() = %s", got)
	}
	for _, tc := range []struct {
		s           string
		tier        Tier
		learn, okay bool
	}{
		{"learn", TierInternet, true, true},
		{"internet", TierInternet, false, true},
		{"none", TierNone, false, true},
		{"maybe", "maybe", false, false},
	} {
		if tier, learn, ok := Choice(tc.s); tier != tc.tier || learn != tc.learn || ok != tc.okay {
			t.Errorf("Choice(%s) = %s %v %v", tc.s, tier, learn, ok)
		}
	}
	for _, c := range Choices() {
		if ChoiceDesc(c).ID() == "" {
			t.Errorf("%s has no description", c)
		}
	}
	if got := ChoiceDesc(Learn).ID(); got != "net_choice_learn" {
		t.Errorf("learn's description is %s", got)
	}
}

// Learning shows after internet alone, in devvm ls as in devvm network.
func TestShown(t *testing.T) {
	for _, tc := range []struct {
		listed   string
		learning bool
		want     string
	}{
		{"internet", true, "internet (learning)"},
		{"internet", false, "internet"},
		{CheckUnenforced, true, CheckUnenforced},
		{"allowlist", true, "allowlist"},
	} {
		if got := Shown(tc.listed, tc.learning); got != tc.want {
			t.Errorf("Shown(%s, %v) = %s, want %s", tc.listed, tc.learning, got, tc.want)
		}
	}
}

// A VM learns while its section says since when, on the internet tier:
// any tier set after ends it, and the section without learning is as it
// was, so a VM that never learned keeps its vm.json.
func TestLearningState(t *testing.T) {
	d := paths.Dirs{Data: t.TempDir()}
	st := newVM(t, d, "devvm-l-00000000000000", "base")
	since := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		tier  Tier
		learn Learning
		on    bool
	}{
		{TierInternet, Learning{Since: since}, true},
		{TierAllowlist, Learning{}, false},
		{TierAllowlist, Learning{Since: since}, false}, // only internet learns
		{TierInternet, Learning{}, false},
	} {
		change(t, st, func(st *state.VM) error { return SetTier(st, tc.tier, tc.learn) })
		if lr := LearningOf(st); lr.On() != tc.on || tc.on && !lr.Since.Equal(since) {
			t.Errorf("%s with %+v: learning %+v", tc.tier, tc.learn, lr)
		}
	}
	if b, _ := os.ReadFile(d.VM(st.Name()).State()); strings.Contains(string(b), "learning") {
		t.Errorf("a VM that doesn't learn has learning in its state:\n%s", b)
	}
}

// Addresses, paste sites and file storage are risky, a subdomain of one
// too, and S3's regional hosts; other hosts aren't.
func TestRiskOf(t *testing.T) {
	for host, want := range map[string]Risk{
		"203.0.113.5":                       RiskAddress,
		"[2001:db8::1]":                     RiskAddress,
		"pastebin.com":                      RiskPaste,
		"PasteBin.com.":                     RiskPaste,
		"gist.githubusercontent.com":        RiskPaste,
		"files.catbox.moe":                  RiskStorage,
		"bucket.s3.amazonaws.com":           RiskStorage,
		"bucket.s3.us-east-1.amazonaws.com": RiskStorage,
		"s3-us-west-2.amazonaws.com":        RiskStorage,
		"ec2.us-east-1.amazonaws.com":       "",
		"registry.npmjs.org":                "",
		"notpastebin.com":                   "",
		"com":                               "",
	} {
		if got := RiskOf(host); got != want {
			t.Errorf("RiskOf(%s) = %q, want %q", host, got, want)
		}
	}
}

// writeLog writes lines as a log's file at path.
func writeLog(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// at is an event's line at a time, of a kind, to host:port, by agent.
func at(when time.Time, kind, host string, port int, agent string) string {
	return `{"time":"` + when.UTC().Format(time.RFC3339) + `","event":"` + kind + `","host":"` + host +
		`","port":` + strconv.Itoa(port) + `,"agent":"` + agent + `"}`
}

// Learned is what the VM reached since it started learning that allowed
// doesn't allow: one row per rule, counted, with the tool that reached it
// most, the risky last. Blocks, links, cache requests, what came before,
// internal addresses and allowed hosts are left out, and a log that lost
// events since is partial. A log that isn't there has none.
func TestLearned(t *testing.T) {
	dir := t.TempDir()
	l := &Log{Path: filepath.Join(dir, "network.jsonl")}
	since := time.Date(2026, 11, 7, 10, 0, 0, 500, time.UTC)
	got, err := l.Learned(since, func(string, int) bool { return false })
	if err != nil || len(got.Hosts) != 0 || got.Partial {
		t.Fatalf("no log: %+v, %v", got, err)
	}
	s := func(n int) time.Time { return since.Add(time.Duration(n) * time.Second) }
	writeLog(t, l.Old(),
		at(s(-60), "tunnel", "before.test", 443, ""),
		at(s(-60), learnEvent, "", 0, ""), // an earlier learning's
		at(s(0), learnEvent, "", 0, ""),
		at(s(0), "tunnel", "registry.npmjs.org", 443, "npm/10.9.2 node/v24"),
	)
	writeLog(t, l.Path,
		at(s(1), "intercept", "registry.npmjs.org", 443, "npm/10.9.2 node/v24"),
		at(s(2), "tunnel", "registry.npmjs.org", 443, "curl/8.5.0"),
		at(s(3), "forward", "example.com", 8080, ""),
		at(s(4), "tunnel", "pastebin.com", 443, "curl/8.5.0"),
		at(s(5), "tunnel", "203.0.113.5", 443, ""),
		at(s(6), "tunnel", "10.0.0.5", 22, ""),
		at(s(7), "tunnel", "github.com", 443, ""),
		at(s(8), "blocked", "blocked.test", 443, ""),
		at(s(9), "link", "db", 5432, ""),
		at(s(10), "nix-cache", "cache.nixos.org", 443, ""),
		at(s(11), "tunnel", "bad host", 443, ""),
		`not json`,
	)
	allowed := func(host string, port int) bool { return host == "github.com" && port == 443 }
	got, err = l.Learned(since, allowed)
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, h := range got.Hosts {
		rows = append(rows, strings.Join([]string{h.Rule, strconv.Itoa(h.Count), h.Agent, string(h.Risk), h.Last}, " "))
	}
	want := []string{
		"example.com:8080 1   " + s(3).Format(time.RFC3339),
		"registry.npmjs.org 3 npm/10.9.2  " + s(2).Format(time.RFC3339),
		"203.0.113.5 1  address " + s(5).Format(time.RFC3339),
		"pastebin.com 1 curl/8.5.0 paste " + s(4).Format(time.RFC3339),
	}
	if !slices.Equal(rows, want) || got.Partial || !got.Since.Equal(since) {
		t.Errorf("Learned:\n%s\nwant\n%s\npartial %v", strings.Join(rows, "\n"), strings.Join(want, "\n"), got.Partial)
	}
	// The older file is gone with the mark: what came before is too, and
	// an earlier learning's mark doesn't count.
	writeLog(t, l.Old(), at(s(-60), learnEvent, "", 0, ""), at(s(1), "tunnel", "registry.npmjs.org", 443, ""))
	if got, err := l.Learned(since, allowed); err != nil || !got.Partial {
		t.Errorf("rotated past since: partial %v, %v", got.Partial, err)
	}
}

// devvm's mark of a VM starting to learn is written through the proxy's
// writer, and devvm network log shows nothing of it, nor its --json.
func TestMarkLearning(t *testing.T) {
	l := &Log{Path: filepath.Join(t.TempDir(), "logs", "network.jsonl")}
	since := time.Now().Add(-time.Second)
	if err := l.MarkLearning("devvm-l-00000000000000"); err != nil {
		t.Fatal(err)
	}
	if got, err := l.Learned(since, func(string, int) bool { return false }); err != nil || got.Partial {
		t.Errorf("marked: partial %v, %v", got.Partial, err)
	}
	if es, err := l.Events(10); err != nil || len(es) != 0 {
		t.Errorf("Events = %+v, %v", es, err)
	}
	b, _ := os.ReadFile(l.Path)
	if _, ok := FormatEvent(strings.TrimSpace(string(b))); ok || !strings.Contains(string(b), `"event":"learn"`) {
		t.Errorf("the mark %q is shown, or isn't one", b)
	}
}

// The proxy's Learned judges with the VM's allowlist tier's own rules,
// read as its proxy reads them: devvm's for every VM, its shared tools',
// and the user's files, so github.com, registry.npmjs.org for a VM with
// node and a host the VM's own file allows are left out, and a deny of
// the user's doesn't make a host allowed. A VM that doesn't learn has
// none.
func TestProxyLearned(t *testing.T) {
	d, st := sandbox(t, "base", "node")
	p := &Proxy{Dirs: d, Assets: assets.FS}
	if got, err := p.Learned(st); err != nil || len(got.Hosts) != 0 {
		t.Fatalf("not learning: %+v, %v", got, err)
	}
	since := time.Now().Add(-time.Minute).UTC()
	change(t, st, func(st *state.VM) error { return SetTier(st, TierInternet, Learning{Since: since}) })
	writeLog(t, d.VM(st.Name()).Policy(), "mine.test", "!denied.test")
	writeLog(t, d.VM(st.Name()).EventLog(),
		at(since.Add(time.Second), "tunnel", "github.com", 443, ""),
		at(since.Add(time.Second), "tunnel", "registry.npmjs.org", 443, ""),
		at(since.Add(time.Second), "tunnel", "mine.test", 443, ""),
		at(since.Add(time.Second), "tunnel", "denied.test", 443, ""),
		at(since.Add(time.Second), "tunnel", "new.test", 443, ""),
	)
	got, err := p.Learned(st)
	var rules []string
	for _, h := range got.Hosts {
		rules = append(rules, h.Rule)
	}
	if err != nil || !slices.Equal(rules, []string{"denied.test", "new.test"}) {
		t.Errorf("Learned = %q, %v", rules, err)
	}
}

// A long User-Agent's first word is kept, at most agentMax runes; the
// tool counted most wins, the first by name of a tie.
func TestAgentWord(t *testing.T) {
	long := strings.Repeat("x", agentMax+5)
	for ua, want := range map[string]string{"": "", "  ": "", "npm/10 node/24": "npm/10", long: long[:agentMax]} {
		if got := agentWord(ua); got != want {
			t.Errorf("agentWord(%q) = %q, want %q", ua, got, want)
		}
	}
	if got := mostOf(map[string]int{"b": 2, "a": 2, "c": 1}); got != "a" {
		t.Errorf("mostOf = %s", got)
	}
	if got := mostOf(nil); got != "" {
		t.Errorf("mostOf(nil) = %s", got)
	}
}
