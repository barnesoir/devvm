package proxy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// A rule from a policy file. One per line, '#' starts a comment:
//
//	example.com       exactly that host
//	*.example.com     any subdomain, at any depth (not example.com itself)
//	**                any host, or address (the floor still refuses internal ones)
//	10.0.0.5, 10.0.0.0/8, fd00::/8   addresses (also needed to reach private ranges, see floor)
//	…:22              only that port; without a port, 443 and 80
//	…:*               any port
//	!rule             deny; a deny beats any allow
//
// Matching is case-insensitive.
type rule struct {
	text   string
	deny   bool
	host   string       // "", "**", "*.example.com" or "example.com"
	prefix netip.Prefix // for address rules
	port   int          // 0: 443 and 80; anyPort: every port
}

// anyPort is a rule's port for :*, every port.
const anyPort = -1

// parseRule reads one rule, strictly: s is the whole rule, without a comment or spaces. It
// refuses anything that wouldn't match as written: a port that isn't 1 to 65535 in digits, a host
// that isn't a plain name (HostOK, with no empty label), a zone, a wildcard other than a leading
// "*." or "**", an address under "*.", an IPv4-mapped prefix shorter than the mapping, anything
// but printable ASCII. A host's one trailing dot is dropped, as requests' are, and a mapped
// prefix is its IPv4 one.
func parseRule(s string) (rule, bool) {
	// Printable ASCII alone: no spaces, and nothing strings.ToLower would fold into ASCII (the
	// Kelvin sign into k).
	if s == "" || strings.ContainsAny(s, "#%") || strings.ContainsFunc(s, func(c rune) bool { return c <= ' ' || c > '~' }) {
		return rule{}, false
	}
	line := strings.ToLower(s)
	r := rule{text: line}
	if rest, ok := strings.CutPrefix(line, "!"); ok {
		r.deny, line = true, rest
	}
	line, port, ok := cutPort(line)
	if !ok {
		return rule{}, false
	}
	r.port = port
	if p, err := netip.ParsePrefix(line); err == nil {
		// An IPv4-mapped prefix is its IPv4 one, as matchAddr unmaps what it judges; one
		// shorter than the mapping's 96 bits isn't a rule.
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return rule{}, false
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		r.prefix = p.Masked()
		return r, true
	}
	if a, err := netip.ParseAddr(line); err == nil {
		r.prefix = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		return r, true
	}
	if line == "**" {
		r.host = line
		return r, true
	}
	h := strings.TrimSuffix(line, ".")
	name := strings.TrimPrefix(h, "*.")
	if _, err := netip.ParseAddr(name); err == nil || strings.ContainsAny(name, "[]*") || !HostOK(name) {
		return rule{}, false
	}
	r.host = h
	return r, true
}

// cutPort takes a rule's port off: host:port, 1.2.3.4:port, [v6]:port or cidr:port, the port 1 to
// 65535 in digits, or * for every port (anyPort). Without one, the rule is as it was and the port
// 0. false: a port that isn't one.
func cutPort(s string) (string, int, bool) {
	h, p, err := net.SplitHostPort(s)
	if err == nil && strings.HasPrefix(s, "[") {
		if a, err := netip.ParseAddr(h); err != nil || !a.Is6() {
			return "", 0, false // brackets hold an IPv6 address alone
		}
	}
	if err != nil {
		i := strings.LastIndex(s, ":")
		if i <= 0 || !strings.Contains(s, "/") || strings.Contains(s[:i], ":") {
			return s, 0, true // no port, or an IPv6 address
		}
		h, p = s[:i], s[i+1:]
	}
	if p == "*" {
		return h, anyPort, true
	}
	n, err := strconv.Atoi(p)
	if err != nil || strings.Trim(p, "0123456789") != "" || n < 1 || n > 65535 {
		return "", 0, false
	}
	return h, n, true
}

// ValidRule reports whether s is one rule, as devvm network allow writes it
// and the proxy takes it from a policy file's line: a host name, *.name, **
// or an address or CIDR (no zone), optionally with a port (or :* for any)
// and a leading !, and no spaces or comment. AllowRule's rules are valid.
func ValidRule(s string) bool {
	_, ok := parseRule(s)
	return ok
}

// A PolicyLine is a line of a policy file that holds more than a comment.
type PolicyLine struct {
	N    int    // its number, from 1
	Text string // as written, without its comment or the spaces around it
	OK   bool   // whether it's a rule (ValidRule): the proxy skips one that isn't
}

// ParsePolicy reads a policy file: one rule a line, '#' starting a comment. It returns each line
// that holds more than a comment, in order, each marked whether it's a rule. The proxy, devvm
// network and devvm doctor all read policy files with it.
func ParsePolicy(text string) []PolicyLine {
	lines, _ := parsePolicy(text)
	return lines
}

// parsePolicy is ParsePolicy, with the rules of the lines that are rules.
func parsePolicy(text string) ([]PolicyLine, []rule) {
	var (
		lines []PolicyLine
		rules []rule
	)
	for i, l := range strings.Split(strings.TrimPrefix(text, "\xef\xbb\xbf"), "\n") { // a byte-order mark isn't text
		s, _, _ := strings.Cut(l, "#")
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		r, ok := parseRule(s)
		lines = append(lines, PolicyLine{N: i + 1, Text: s, OK: ok})
		if ok {
			rules = append(rules, r)
		}
	}
	return lines, rules
}

func (r rule) portOK(port int) bool {
	switch r.port {
	case 0:
		return port == 443 || port == 80
	case anyPort:
		return port >= 1 && port <= 65535
	}
	return r.port == port
}

// matchHost: does a host-name rule cover host (lower-case, no port)?
func (r rule) matchHost(host string) bool {
	switch {
	case r.host == "":
		return false
	case r.host == "**":
		return true
	case strings.HasPrefix(r.host, "*."):
		return strings.HasSuffix(host, r.host[1:])
	default:
		return r.host == host
	}
}

// matchAddr: does an address rule cover a? A NAT64 address also matches as the IPv4 address in it,
// as internal() judges it, so a deny for an IPv4 address holds on IPv6-only networks too.
func (r rule) matchAddr(a netip.Addr) bool {
	if !r.prefix.IsValid() {
		return false
	}
	a = a.Unmap()
	if r.prefix.Contains(a) {
		return true
	}
	v4, ok := nat64IPv4(a)
	return ok && r.prefix.Contains(v4)
}

// policy is the union of devvm's built-in policies, read once, and several files, each re-read when
// it changes (watched). A file that's gone has no rules; one that can't be read keeps its last
// rules and broken deny, logged once (a deny dropped for a moment would let through).
type policy struct {
	// builtin is the built-in policies' rules (readBuiltins), ahead of the files'.
	builtin []rule
	files   []*watched[policyFile]
	// open allows every host and address on every port, the floor's included: no rule applies
	// (Config.Open).
	open bool
}

// policyFile is what one policy file holds.
type policyFile struct {
	rules []rule
	// broken is the first of its lines that starts with ! and isn't a rule (BrokenDeny): while any
	// file has one, the policy denies everything.
	broken *PolicyLine
}

// PolicyMax bounds a policy file that the proxy, devvm network and devvm doctor read.
const PolicyMax = 1 << 20

// newPolicy is the policy of builtin, files and denies, whose denies alone apply, logging to l,
// the proxy's own log, what was read and what was skipped.
func newPolicy(builtin []rule, files, denies []string, l *log.Logger) *policy {
	p := &policy{builtin: builtin}
	add := func(f string, deniesOnly bool) {
		p.files = append(p.files, &watched[policyFile]{
			// A FIFO or a device there (a link to /dev/zero) is refused, not read (ReadRegular).
			path: f, follow: true, keep: true,
			read:   func(path string) ([]byte, error) { return ReadRegular(path, PolicyMax) },
			parse:  func(b []byte) (policyFile, error) { return loadPolicy(f, string(b), deniesOnly, l), nil },
			onFail: func(err error) { l.Printf("policy %v; its last rules kept", err) },
		})
	}
	for _, f := range files {
		add(f, false)
	}
	for _, f := range denies {
		add(f, true)
	}
	return p
}

// readBuiltins reads the built-in policies names, paths in devvm's own files own, once, in order,
// logging each to l. Each is devvm's own, so one that's missing or holds a line that isn't a rule
// is devvm's bug: an error, and the proxy refuses to start, rather than run with fewer rules than
// devvm meant.
func readBuiltins(own fs.FS, names []string, l *log.Logger) ([]rule, error) {
	if len(names) > 0 && own == nil {
		return nil, errors.New("built-in policies need devvm's own files")
	}
	var out []rule
	for _, n := range names {
		b, err := fs.ReadFile(own, n)
		if err != nil {
			return nil, fmt.Errorf("built-in policy %s: %w", n, err)
		}
		lines, rs := parsePolicy(string(b))
		for _, l := range lines {
			if !l.OK {
				return nil, fmt.Errorf("built-in policy %s:%d isn't a rule: %q", n, l.N, l.Text)
			}
		}
		l.Printf("built-in policy %s: %d rules", n, len(rs))
		out = append(out, rs...)
	}
	return out, nil
}

// BrokenDeny reports whether l is a line that reads as a deny, starting with !, but isn't a
// rule. Its proxy can't know what it would deny, so it denies everything while the line is there.
func BrokenDeny(l PolicyLine) bool { return !l.OK && strings.HasPrefix(l.Text, "!") }

// all returns the policy's rules, the built-in policies' first, and while a file has a broken deny
// (BrokenDeny), why the policy denies everything.
func (p *policy) all() ([]rule, string) {
	out := slices.Clone(p.builtin)
	why := ""
	for _, w := range p.files {
		pf := w.get()
		out = append(out, pf.rules...)
		if l := pf.broken; l != nil && why == "" {
			why = fmt.Sprintf("%s:%d isn't a rule but reads as a deny (%q), so this VM's proxy denies everything until it's fixed", w.path, l.N, l.Text)
		}
	}
	return out, why
}

// loadPolicy is file f's rules from its text b, its denies alone with deniesOnly, logging to l
// each line that isn't a rule and noting the first broken deny.
func loadPolicy(f, b string, deniesOnly bool, l *log.Logger) policyFile {
	lines, rs := parsePolicy(b)
	if deniesOnly {
		rs = slices.DeleteFunc(rs, func(r rule) bool { return !r.deny })
	}
	pf := policyFile{rules: rs}
	for _, line := range lines {
		switch {
		case BrokenDeny(line):
			l.Printf("%s:%d: not a rule but reads as a deny, so everything is denied: %q", f, line.N, line.Text)
			if pf.broken == nil {
				pf.broken = &line
			}
		case !line.OK:
			l.Printf("%s:%d: not a rule, skipped: %q", f, line.N, line.Text)
		}
	}
	l.Printf("policy %s: %d rules", f, len(rs))
	return pf
}

// openRule is what an open policy logs as the rule that allowed a request.
const openRule = "open"

// decide whether host:port may be reached. host is a name or an address literal. It returns the
// matching rule's text, or why not.
func (p *policy) decide(host string, port int) (bool, string) {
	ok, why, _ := p.verdict(host, port)
	return ok, why
}

// verdict is decide, and whether a refusal is one no allow rule would lift: a broken deny's.
func (p *policy) verdict(host string, port int) (bool, string, bool) {
	if p.open {
		return true, openRule, false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	rs, broken := p.all()
	if broken != "" {
		return false, broken, true
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	isAddr := err == nil
	match := func(r rule) bool {
		if !r.portOK(port) {
			return false
		}
		if isAddr {
			// ** is any host, an address too; the floor still refuses an
			// internal one that no address rule names (addrAllowed).
			return r.matchAddr(addr) || r.host == "**"
		}
		return r.matchHost(host)
	}
	for _, r := range rs {
		if r.deny && match(r) {
			return false, "denied by " + r.text, false
		}
	}
	for _, r := range rs {
		if !r.deny && match(r) {
			return true, r.text, false
		}
	}
	return false, "not on the allowlist", false
}

// Allowlist is a set of policies as a VM's proxy reads them, read once: what devvm network lock
// judges the hosts a learning VM reached with, so it leaves out what the VM's allowlist tier
// already allows, by the proxy's own rules.
type Allowlist struct{ p *policy }

// ReadAllowlist reads builtin, paths in devvm's own files own, then files, whose every rule
// applies, and denies, whose denies alone apply, as Config's BuiltinPolicies, Policies and
// DenyPolicies have them. A built-in policy that's missing or holds a line that isn't a rule is
// an error, as it is for the proxy.
func ReadAllowlist(own fs.FS, builtin, files, denies []string) (Allowlist, error) {
	l := log.New(io.Discard, "", 0)
	rs, err := readBuiltins(own, builtin, l)
	if err != nil {
		return Allowlist{}, err
	}
	return Allowlist{newPolicy(rs, files, denies, l)}, nil
}

// Allows reports whether the policies allow host:port, as the proxy decides it by its rules,
// before the floor of internal addresses: a deny beats any allow, and while a file has a broken
// deny nothing is allowed.
func (p Allowlist) Allows(host string, port int) bool {
	ok, _, _ := p.p.verdict(host, port)
	return ok
}

// byName: an allow rule that names host, as itself or under *.domain, for port: one that's more
// than **, which allows any host. None while a deny is broken.
func (p *policy) byName(host string, port int) bool {
	if p.open {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	rs, broken := p.all()
	if broken != "" {
		return false
	}
	for _, r := range rs {
		if !r.deny && r.host != "**" && r.portOK(port) && r.matchHost(host) {
			return true
		}
	}
	return false
}

// addrAllowed: an explicit address rule for a (needed to pass the floor), and no deny for it.
func (p *policy) addrAllowed(a netip.Addr, port int) bool {
	if p.open {
		return true
	}
	if p.addrDenied(a, port) {
		return false
	}
	rs, broken := p.all()
	if broken != "" {
		return false
	}
	for _, r := range rs {
		if !r.deny && r.portOK(port) && r.matchAddr(a) {
			return true
		}
	}
	return false
}

// addrDenied: a deny rule for address a, or a broken deny (every address). A deny beats any
// allow, including a host rule whose name resolves to a, so every address the proxy dials is
// checked against it.
func (p *policy) addrDenied(a netip.Addr, port int) bool {
	if p.open {
		return false
	}
	rs, broken := p.all()
	if broken != "" {
		return true
	}
	for _, r := range rs {
		if r.deny && r.portOK(port) && r.matchAddr(a) {
			return true
		}
	}
	return false
}
