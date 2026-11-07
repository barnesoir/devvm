package netpolicy

import (
	"cmp"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/devvmhq/devvm/internal/image"
	"github.com/devvmhq/devvm/internal/proxy"
	"github.com/devvmhq/devvm/internal/state"
	"github.com/devvmhq/devvm/internal/tools"
)

// Risk is why devvm network lock leaves a learned host unticked: each is
// an easy way to send data out. "" for none.
type Risk string

// The risks, as devvm network lock --json names them.
const (
	RiskAddress Risk = "address" // an address, not a name
	RiskPaste   Risk = "paste"   // a paste site
	RiskStorage Risk = "storage" // file storage or file sharing
)

// riskyHosts are the paste sites and file storage hosts devvm network
// lock leaves unticked, each matched as itself and as any of its
// subdomains: few, and well known, as the docs say. devvm's own rules
// leave them out too (layers/base.policy).
func riskyHosts() map[string]Risk {
	return map[string]Risk{
		"pastebin.com": RiskPaste, "paste.ee": RiskPaste, "hastebin.com": RiskPaste, "termbin.com": RiskPaste,
		"dpaste.org": RiskPaste, "paste.rs": RiskPaste, "rentry.co": RiskPaste, "ghostbin.site": RiskPaste,
		"gist.githubusercontent.com": RiskPaste, "webhook.site": RiskPaste,
		"transfer.sh": RiskStorage, "file.io": RiskStorage, "0x0.st": RiskStorage, "temp.sh": RiskStorage,
		"catbox.moe": RiskStorage, "wetransfer.com": RiskStorage, "mega.nz": RiskStorage,
		"dropbox.com": RiskStorage, "dropboxusercontent.com": RiskStorage, "drive.google.com": RiskStorage,
		"storage.googleapis.com": RiskStorage, "blob.core.windows.net": RiskStorage,
		"r2.cloudflarestorage.com": RiskStorage, "s3.amazonaws.com": RiskStorage,
	}
}

// RiskOf returns why host is risky to allow (Risk): an address, a host of
// riskyHosts or under one, or one of S3's regional hosts
// (bucket.s3.us-east-1.amazonaws.com); "" for any other.
func RiskOf(host string) Risk {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return RiskAddress
	}
	risky := riskyHosts()
	for h := host; h != ""; {
		if r, ok := risky[h]; ok {
			return r
		}
		_, rest, ok := strings.Cut(h, ".")
		if !ok {
			break
		}
		h = rest
	}
	if strings.HasSuffix(host, ".amazonaws.com") && slices.ContainsFunc(strings.Split(host, "."), func(l string) bool {
		return l == "s3" || strings.HasPrefix(l, "s3-") || strings.HasPrefix(l, "s3.")
	}) {
		return RiskStorage
	}
	return ""
}

// Learned is a host and port a learning VM reached that its allowlist
// tier doesn't allow, as devvm network lock offers it.
type Learned struct {
	Rule  string // the rule devvm network allow takes for it (proxy.AllowRule)
	Host  string
	Port  int
	Count int    // the connections and requests its proxy allowed
	Last  string // when it was last reached, as the log has it
	Agent string // the tool its requests named most (their User-Agent's first word), "" for none
	Risk  Risk
}

// LearnedHosts is what a learning VM reached, since it started learning,
// that its allowlist tier doesn't allow: the hosts without a risk first,
// then the risky ones, each by its rule.
type LearnedHosts struct {
	Since time.Time
	Hosts []Learned
	// Partial is whether the log lost events since then: the proxy
	// rotated it past its limit, keeping one older file, and the mark of
	// the VM starting to learn is gone with the file before.
	Partial bool
}

// Learned returns what st's VM reached since it started learning that its
// allowlist tier wouldn't allow, by its proxy's own rules (the VM's
// policies on that tier, proxy.ReadAllowlist): none for a VM that doesn't
// learn.
func (p *Proxy) Learned(st *state.VM) (LearnedHosts, error) {
	lr := LearningOf(st)
	if !lr.On() {
		return LearnedHosts{}, nil
	}
	vm := st.Name()
	set := Policies(p.Dirs, vm, TierAllowlist, image.Name(st.Image), tools.Names(st))
	al, err := proxy.ReadAllowlist(p.Assets, set.Builtin, set.Files, set.Denies)
	if err != nil {
		return LearnedHosts{}, err
	}
	return NewLog(p.Dirs, vm).Learned(lr.Since, al.Allows)
}

// reached is whether an event is a connection or request the proxy let
// through to its host: a tunnel, a decrypted one, or a forwarded request.
func reached(e Event) bool {
	return e.Event == "tunnel" || e.Event == "intercept" || e.Event == "forward"
}

// learnEvent is the event devvm writes in a VM's log as the VM starts
// learning (MarkLearning), so Learned knows whether the log still goes
// back that far. devvm network log doesn't show it.
const learnEvent = "learn"

// MarkLearning writes in the log that its VM, vm, starts learning now,
// through the proxy's own writer (AppendEvent).
func (l *Log) MarkLearning(vm string) error { return AppendEvent(l.Path, vm, Event{Event: learnEvent}) }

// Learned returns the hosts and ports the log's VM reached since then
// (the previous file's too) that allowed doesn't allow, one per rule: an
// address that isn't public is left out, as is a host the policy doesn't
// take. A log that isn't there has none; one without the mark of the VM
// starting to learn then (MarkLearning), which the proxy's rotation
// dropped, is partial.
func (l *Log) Learned(since time.Time, allowed func(host string, port int) bool) (LearnedHosts, error) {
	out := LearnedHosts{Since: since}
	from := since.Truncate(time.Second)
	rows := map[string]*Learned{}
	agents := map[string]map[string]int{}
	marked := false
	err := l.each(func(line string) {
		var e Event
		if json.Unmarshal([]byte(line), &e) != nil || e.Event == "" {
			return
		}
		at, err := time.Parse(time.RFC3339, e.Time)
		if err != nil || at.Before(from) {
			return
		}
		if e.Event == learnEvent {
			marked = true
		}
		if !reached(e) {
			return
		}
		rule, ok := proxy.AllowRule(e.Host, e.Port)
		if a, err := netip.ParseAddr(strings.Trim(e.Host, "[]")); !ok || err == nil && !proxy.Public(a) || allowed(e.Host, e.Port) {
			return
		}
		r := rows[rule]
		if r == nil {
			r = &Learned{Rule: rule, Host: e.Host, Port: e.Port, Risk: RiskOf(e.Host)}
			rows[rule], agents[rule] = r, map[string]int{}
		}
		r.Count++
		r.Last = e.Time
		if a := agentWord(e.Agent); a != "" {
			agents[rule][a]++
		}
	})
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	} else if err != nil {
		return out, err
	}
	out.Partial = !marked
	for rule, r := range rows {
		r.Agent = mostOf(agents[rule])
		out.Hosts = append(out.Hosts, *r)
	}
	slices.SortFunc(out.Hosts, func(a, b Learned) int {
		risky := func(l Learned) int {
			if l.Risk != "" {
				return 1
			}
			return 0
		}
		return cmp.Or(cmp.Compare(risky(a), risky(b)), cmp.Compare(a.Rule, b.Rule))
	})
	return out, nil
}

// agentMax bounds the tool a learned host shows, so a long User-Agent
// can't push its row off the terminal.
const agentMax = 40

// agentWord is the tool a User-Agent names: its first word, such as
// npm/10.9.2 or curl/8.5.0, at most agentMax runes.
func agentWord(ua string) string {
	f := strings.Fields(ua)
	if len(f) == 0 {
		return ""
	}
	if r := []rune(f[0]); len(r) > agentMax {
		return string(r[:agentMax])
	}
	return f[0]
}

// mostOf is the key counted most, the first by name of those counted as
// often; "" for none.
func mostOf(counts map[string]int) string {
	best, n := "", 0
	for _, k := range slices.Sorted(maps.Keys(counts)) {
		if counts[k] > n {
			best, n = k, counts[k]
		}
	}
	return best
}
