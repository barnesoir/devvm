// Package proxy is the network tier's enforcement point for one devvm VM, run as devvm _proxy.
//
// devvm starts one per VM, listening on a loopback port. The VM's Lima hostagent runs under a
// Seatbelt profile, or a restricted QEMU network, that lets the VM reach nothing else, so every
// connection the VM makes goes through here. Other programs on the host can reach the port too, so
// requests must carry the VM's password (its config's, -config: see config.go), and the VM's
// placeholders end in its own key:
//
//   - CONNECT host:port and absolute-form requests (GET http://host/…) are checked against the
//     policy: devvm's built-in policies, read from its own files (IO.FS) once, and the user's
//     policy files (see policy.go); allowed ones are tunneled or forwarded, untouched.
//   - Names are resolved here, and connections to loopback, private, link-local and the host's own
//     addresses are refused unless a rule names the address (the "floor").
//   - A tunnel that starts with a TLS ClientHello must name the CONNECT host in its SNI.
//   - Hosts with a bound secret (Config.Secrets) are intercepted on :443 instead, to put the secret in
//     (see secrets.go). Everything else passes unread.
//   - Every decision goes to a JSON-lines log, and http://devvm.proxy/blocked lists recent blocks
//     (/blocked/new: those since the VM's last prompt; /ca.pem serves the CA).
//   - With Config.NixCache, http://devvm.proxy/nix/ is a Nix binary cache shared by VMs, which only the
//     host fills, from cache.nixos.org, checking what it keeps (see nixcache.go).
//   - With Config.Links, the VM's links (NAME:PORT, from the list devvm _links writes) go to their
//     sockets on the host before any rule, their bytes as they are (see links.go).
//
// It exits when the VM's hostagent does (Config.Lifeline). Standard library only, and internal/daemon,
// which is too: it prints nothing itself, but writes to the streams devvm hands Main.
//
// Everything one proxy runs with and keeps between connections is in its server, which Main makes
// from the config (newServer): the package keeps no state of its own, so each test makes a server
// of its own, and none sees another's.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/devvmhq/devvm/internal/daemon"
)

// newFlags defines devvm _proxy's one flag, -config, on a flag set of its own, writing into path. It
// takes one dash or two.
func newFlags(path *string) *flag.FlagSet {
	fs := flag.NewFlagSet("devvm _proxy", flag.ContinueOnError)
	fs.StringVar(path, "config", "", "the proxy's config (Config, JSON, mode 600): run the proxy with it (config.go)")
	return fs
}

// --- the server ---

// server is one proxy: what its config gave it, and what it keeps between connections, each part
// under a lock of its own. newServer makes it from a Config.
type server struct {
	vm       string      // Config.VM, for the log
	password string      // the VM's password (Config.Password); empty: no check
	log      *log.Logger // its own log lines (what it loaded, what failed), not events
	events   *events
	egress   *egress  // where a connection may go: the policy, the floor, the company proxy
	secrets  *secrets // Config.Secrets: the bindings and their values
	captures *captures
	ca       *ca // Config.CA, and its next (Config.CANext), for interception; nil: none
	// upstreamCAs is what the proxy's own TLS connections trust: nil, the system roots;
	// Config.UpstreamCAs, the user's CAs besides them.
	upstreamCAs *x509.CertPool
	// interceptPorts are the ports a host with a bound secret is intercepted on: HTTPS's alone, so
	// anything else to a bound host (SSH on :22, …) is tunneled.
	interceptPorts map[int]bool
	links          links
	nix            *nixCache
	// connects holds a slot for each CONNECT open (maxConnects); connectsFull is whether the
	// proxy's log has said the limit was reached since a tunnel last ended.
	connects     chan struct{}
	connectsFull atomic.Bool
}

// maxConnects is how many CONNECTs a VM's proxy carries at once, tunnels and interceptions alike:
// four times what a browser keeps open at most (Chrome's 256), and many times a package manager's
// (npm's 15 sockets, uv's 50 downloads), so several builds and installs at once fit, while a VM that opens tunnels without end can't take every descriptor
// the proxy has (two each).
const maxConnects = 1024

// newServer makes the server c describes, logging to l and its events to out: it reads its CA,
// the company proxy's settings, the built-in policies (from std.FS) and the user's policy files,
// and opens the Nix cache. Values come from std.Secret.
func newServer(c Config, std IO, l *log.Logger, out io.Writer) (*server, error) {
	ev := &events{vm: c.VM, out: out}
	s := &server{
		vm: c.VM, password: c.Password, log: l, events: ev,
		secrets:        newSecrets(c.Secrets, std.Secret, l),
		captures:       newCaptures(c.Captures, std.Capture),
		interceptPorts: map[int]bool{443: true},
		links:          newLinks(c.Links, c.LinkSockets, c.VM, l, ev),
		connects:       make(chan struct{}, maxConnects),
	}
	var err error
	if c.CA != "" {
		if s.ca, err = loadCA(c.CA, c.CAKey); err != nil {
			return nil, err
		}
	}
	if c.CANext != "" {
		if s.ca.next, err = loadCA(c.CANext, c.CANextKey); err != nil {
			return nil, err
		}
	}
	if c.UpstreamCAs != "" {
		if s.upstreamCAs, err = upstreamPool([]byte(c.UpstreamCAs)); err != nil {
			return nil, err
		}
		s.secrets.roots = s.upstreamCAs
	}
	var up upstreams
	if c.Upstream != nil {
		if up, err = newUpstreams(*c.Upstream, std.Secret); err != nil {
			return nil, err
		}
		l.Printf("%s", up.names())
	}
	up.unresolved = c.UpstreamUnresolved
	s.secrets.route = up.host
	if s.secrets.route == nil {
		s.secrets.route = direct
	}
	rs, err := readBuiltins(std.FS, c.BuiltinPolicies, l)
	if err != nil {
		return nil, err
	}
	own := &hostAddrs{}
	own.load()
	pol := newPolicy(rs, c.Policies, c.DenyPolicies, l)
	pol.open = c.Open
	if c.Open {
		l.Printf("open: every host and address, no rules")
	}
	s.egress = &egress{pol: pol, own: own, up: up, log: l}
	s.egress.pol.all()
	maxSize := c.NixCacheMax
	if maxSize == 0 {
		maxSize = NixCacheDefault
	}
	s.nix = newNixCache(c.NixCache, maxSize, s.egress, ev, l, s.upstreamCAs)
	if err := s.nix.open(); err != nil {
		return nil, err
	}
	return s, nil
}

// --- who may use the proxy ---

// ProxyUser is the user every request names with its password, a VM's or a build's own, as devvm's
// backends put it in a guest's proxy settings.
const ProxyUser = "devvm"

// authorized: the request carries the VM's password (Basic, user ProxyUser). Lima's hostagent makes the
// VM's connections, so the port alone can't tell the VM apart from anything else on the host that
// reaches it: other VMs, other users. Inside an intercepted tunnel there's no proxy header: the
// CONNECT that opened it was checked.
func (s *server) authorized(r *http.Request) bool {
	if s.password == "" {
		return true
	}
	v := r.Header.Get("Proxy-Authorization")
	if len(v) < 6 || !strings.EqualFold(v[:6], "basic ") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[6:]))
	return err == nil && subtle.ConstantTimeCompare(raw, []byte(ProxyUser+":"+s.password)) == 1
}

// --- events ---

// Event is one line of the event log, as JSON: a decision about a
// connection or a request. devvm network log reads them.
type Event struct {
	Time    string   `json:"time"`
	VM      string   `json:"vm"`
	Event   string   `json:"event"` // tunnel, intercept, forward, login, blocked
	Host    string   `json:"host"`
	Port    int      `json:"port"`
	Method  string   `json:"method,omitempty"`
	Path    string   `json:"path,omitempty"`
	Rule    string   `json:"rule,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	Agent   string   `json:"agent,omitempty"`
	Secrets []string `json:"secrets,omitempty"` // names of secrets put in, never values
	// Login is the agent whose login a token endpoint's reply held (a login event): saved on the
	// host, the VM given placeholders. Never a value.
	Login   string `json:"login,omitempty"`
	Refused bool   `json:"refused,omitempty"` // blocked whatever the allowlist says: no rule allows it
	// The company proxy it went through (Config.Upstream), as host:port: never its credentials.
	Upstream string `json:"upstream,omitempty"`
	// The VM a link's connection went to (devvm _links's events, Host the link's name): never the proxy's.
	Target string `json:"target,omitempty"`
}

// A block and its number (the first is 1), for /blocked/new.
type numbered struct {
	n int
	e Event
}

// events is a proxy's event log (Config.Log, else IO.Stdout) and the blocks it keeps for
// /blocked, all under its lock.
type events struct {
	vm     string // Config.VM: every event's
	mu     sync.Mutex
	out    io.Writer
	recent []numbered // the last blocks, for /blocked
	blocks int        // blocks so far
}

// maxHeaderBytes bounds the headers of a request to the proxy: 64 KiB, many times a real client's,
// so the VM can't make it hold a megabyte for each.
const maxHeaderBytes = 64 << 10

// eventFieldMax bounds what the VM chose that an event records, its request's path and User-Agent,
// so a VM can't fill the log with a few requests.
const eventFieldMax = 512

// capField is s cut to eventFieldMax bytes, at a rune's start.
func capField(s string) string {
	if len(s) <= eventFieldMax {
		return s
	}
	i := eventFieldMax
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i]
}

// record writes e to the log, as the VM's, now, its path and User-Agent capped (capField), and
// keeps it among the recent blocks when it's one.
func (ev *events) record(e Event) {
	e.Time, e.VM = time.Now().UTC().Format(time.RFC3339), ev.vm
	e.Path, e.Agent = capField(e.Path), capField(e.Agent)
	b, _ := json.Marshal(e)
	ev.mu.Lock()
	defer ev.mu.Unlock()
	fmt.Fprintln(ev.out, string(b))
	if e.Event == "blocked" {
		ev.blocks++
		ev.recent = append(ev.recent, numbered{ev.blocks, e})
		if len(ev.recent) > 50 {
			ev.recent = ev.recent[len(ev.recent)-50:]
		}
	}
}

// blocked is a copy of the recent blocks, and how many blocks there have been, for /blocked and
// /blocked/new.
func (ev *events) blocked() ([]numbered, int) {
	ev.mu.Lock()
	defer ev.mu.Unlock()
	return slices.Clone(ev.recent), ev.blocks
}

// newBlocks answers /blocked/new?after=N for the VM's prompt: the number of blocks so far on the first
// line, then the blocks after the Nth, each rule once, and the command that allows them. No N (a new
// shell) means none; an N past the count means the proxy restarted, so every block since counts.
func newBlocks(rs []numbered, count int, after string) string {
	var b strings.Builder
	fmt.Fprintln(&b, count)
	n, err := strconv.Atoi(after)
	if err != nil {
		return b.String()
	}
	if n > count {
		n = 0
	}
	var rules []string
	seen := map[string]bool{}
	for _, r := range rs {
		if r.n <= n {
			continue
		}
		if r.e.Refused {
			fmt.Fprintf(&b, "devvm: refused %s %s%s (%s)\n", r.e.Method, r.e.Host, r.e.Path, r.e.Reason)
			continue
		}
		rule := ruleFor(r.e.Host, r.e.Port)
		if seen[rule] {
			continue
		}
		seen[rule] = true
		rules = append(rules, rule)
		fmt.Fprintf(&b, "devvm: blocked %s:%d (%s)\n", r.e.Host, r.e.Port, r.e.Reason)
	}
	if len(rules) > 0 {
		fmt.Fprintf(&b, "To allow, run this on the host:\ndevvm network allow %s\n", strings.Join(rules, " "))
	}
	return b.String()
}

// --- destinations ---

// hostAddrs is the host's own addresses, read again every 30 seconds: they change (a new network,
// IPv6 temporary addresses).
type hostAddrs struct {
	mu    sync.Mutex
	addrs map[netip.Addr]bool
	at    time.Time
}

func (h *hostAddrs) load() {
	addrs, _ := net.InterfaceAddrs()
	own := map[netip.Addr]bool{}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			own[p.Addr().Unmap()] = true
		}
	}
	h.mu.Lock()
	h.addrs, h.at = own, time.Now()
	h.mu.Unlock()
}

func (h *hostAddrs) has(a netip.Addr) bool {
	h.mu.Lock()
	stale := time.Since(h.at) > 30*time.Second
	h.mu.Unlock()
	if stale {
		h.load()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.addrs[a]
}

// Ranges that aren't the public internet beyond what netip's predicates cover: CGNAT, "this network",
// IETF protocol assignments, benchmarking, reserved, local-use NAT64, IPv4-compatible IPv6 (::a.b.c.d,
// deprecated) and site-local IPv6 (deprecated, still routed by some systems).
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("fec0::/10"),
}

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// nat64IPv4: the IPv4 address in a NAT64 address (64:ff9b::a.b.c.d).
func nat64IPv4(a netip.Addr) (netip.Addr, bool) {
	if !nat64.Contains(a) {
		return netip.Addr{}, false
	}
	b := a.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
}

// internal: addresses a VM must not reach without an explicit rule: the host itself (h) and its
// networks. A NAT64 address (64:ff9b::a.b.c.d, on IPv6-only networks) is judged by the IPv4 address
// in it.
func (h *hostAddrs) internal(a netip.Addr) bool {
	a = a.Unmap()
	if v4, ok := nat64IPv4(a); ok {
		return h.internal(v4)
	}
	return !Public(a) || h.has(a)
}

// Public reports whether a is an address of the public internet: none of the ranges the floor
// refuses (loopback, private, link-local, multicast and the rest of notPublic), a NAT64 address
// judged by the IPv4 address in it. This machine's own public addresses are the floor's too
// (hostAddrs), which Public doesn't know. devvm network lock leaves out what isn't.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	if v4, ok := nat64IPv4(a); ok {
		a = v4
	}
	for _, p := range notPublic {
		if p.Contains(a) {
			return false
		}
	}
	return !a.IsLoopback() && !a.IsPrivate() && !a.IsLinkLocalUnicast() && !a.IsLinkLocalMulticast() &&
		!a.IsMulticast() && !a.IsUnspecified() && !a.IsInterfaceLocalMulticast()
}

// egress decides where a connection may go, and makes it: the policy, the floor of internal
// addresses (the host's own among them), and the company proxy.
type egress struct {
	pol *policy
	own *hostAddrs
	up  upstreams
	log *log.Logger // the proxy's own log: why a name didn't resolve
}

// reasonUnresolvable and reasonConnectFailed are the reasons the VM gets when a name doesn't
// resolve or a connection fails. Why goes to the proxy's own log alone: the resolver's error can
// name the host's DNS server, and the company proxy's names its address.
const (
	reasonUnresolvable  = "can't resolve it; see proxy.log on the host"
	reasonConnectFailed = "connect failed; see proxy.log on the host"
)

var errFloor = errors.New("resolves to an internal address")

// resolve host to the addresses that may be dialed for port. Callers dial these, not the name, so
// a second DNS answer can't swap in an internal address.
func (e *egress) resolve(ctx context.Context, host string, port int) ([]netip.Addr, error) {
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		addrs = []netip.Addr{a.Unmap()}
	} else {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, a := range ips {
			addrs = append(addrs, a.Unmap())
		}
	}
	var ok []netip.Addr
	for _, a := range addrs {
		if !e.pol.addrDenied(a, port) && (!e.own.internal(a) || e.pol.addrAllowed(a, port)) {
			ok = append(ok, a)
		}
	}
	if len(ok) == 0 {
		return nil, errFloor
	}
	return ok, nil
}

func (e *egress) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	addrs, err := e.resolve(ctx, host, port)
	if err != nil {
		return nil, err
	}
	if port < 1 || port > 65535 { // the policy allows none of these; never dial one wrapped around
		return nil, fmt.Errorf("port %d", port)
	}
	d := net.Dialer{Timeout: 15 * time.Second}
	for _, a := range addrs {
		c, err2 := d.DialContext(ctx, "tcp", netip.AddrPortFrom(a, uint16(port)).String())
		if err2 == nil {
			return c, nil
		}
		err = err2
	}
	return nil, err
}

// --- the proxy ---

// HostOK reports whether h is a host name (letters, digits, '-', '_', '.') or an address. The VM
// chooses the host, and it ends up in the log, in the policy and in the allow command devvm
// suggests for the host's shell; agentlogin checks an MCP server's host with it before it goes into
// a VM's allowlist.
// A name is splitHostPort's form, with no trailing dot, and has no empty label: a company proxy
// that drops trailing dots (evil.test.., which splitHostPort leaves as evil.test.) would reach a
// host that a deny of evil.test never matched.
func HostOK(h string) bool {
	if a, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return a.Zone() == "" // a zone (fe80::1%eth0) is any text
	}
	if h == "" || len(h) > 253 || slices.Contains(strings.Split(h, "."), "") {
		return false
	}
	// An address in a shorthand netip doesn't read (127.1, 2130706433, 0x7f000001, 10.1): no name
	// ends in such a label, and a company proxy or resolver that reads it as inet_aton does would
	// reach an address the floor never judged.
	if last := h[strings.LastIndexByte(h, '.')+1:]; strings.HasPrefix(last, "0x") || strings.Trim(last, "0123456789") == "" {
		return false
	}
	for _, c := range h {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// splitHostPort: the host, lowercased and without a trailing dot (so the policy, bindings, SNI check
// and log all see one form), and the port (def when there's none).
func splitHostPort(hp string, def int) (string, int) {
	norm := func(h string) string { return strings.TrimSuffix(strings.ToLower(h), ".") }
	h, p, err := net.SplitHostPort(hp)
	if err != nil {
		return norm(strings.Trim(hp, "[]")), def
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return norm(h), def
	}
	return norm(h), n
}

func (s *server) block(w http.ResponseWriter, e Event) {
	e.Event = "blocked"
	s.events.record(e)
	w.Header().Set("X-Devvm-Blocked", e.Host)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	if e.Refused { // no rule would allow it: no allow command
		fmt.Fprintf(w, "devvm: %s:%d is refused (%s).\n", e.Host, e.Port, e.Reason)
		return
	}
	fmt.Fprintf(w, "devvm: %s:%d is blocked (%s). Allow it on the host with: devvm network allow %s\n",
		e.Host, e.Port, e.Reason, ruleFor(e.Host, e.Port))
}

func ruleFor(host string, port int) string {
	if port == 443 || port == 80 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// AllowRule is the rule that allows host:port, for a devvm network allow
// command; false for a host the policy doesn't take, which a logged event
// can't have, or a log that was edited.
func AllowRule(host string, port int) (string, bool) {
	if !HostOK(host) || port < 1 || port > 65535 {
		return "", false
	}
	return ruleFor(host, port), true
}

// check runs the policy and the floor; on success it returns the rule that allowed host:port. plain
// is a plain HTTP request, which goes through HTTP_PROXY's upstream rather than HTTPS_PROXY's.
func (e *egress) check(ctx context.Context, host string, port int, plain bool) (string, string) {
	rule, why, _ := e.checkRefused(ctx, host, port, plain)
	return rule, why
}

// checkRefused is check, and whether a refusal is one no allow rule would lift (a broken deny's),
// which its event marks Refused.
func (e *egress) checkRefused(ctx context.Context, host string, port int, plain bool) (string, string, bool) {
	ok, rule, refused := e.pol.verdict(host, port) // rule: the allowing rule, or why not
	if !ok {
		return "", rule, refused
	}
	if why := e.floorCheck(ctx, host, port, plain); why != "" {
		return "", why, false
	}
	return rule, "", false
}

// floorCheck is check past the rules for an allowed host: the address floor, or the company
// proxy's. It returns why not, or "".
func (e *egress) floorCheck(ctx context.Context, host string, port int, plain bool) string {
	floor := func() error { _, err := e.resolve(ctx, host, port); return err }
	if e.up.route(host, port, plain) != nil {
		floor = func() error { return e.floorUpstream(ctx, host, port) }
	}
	err := floor()
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errFloor):
		return "it " + err.Error() + "; allow the address itself to reach it"
	case errors.Is(err, errUnresolved):
		return err.Error()
	default:
		e.log.Printf("%s:%d: can't resolve it: %v", host, port, err)
		return reasonUnresolvable
	}
}

func (s *server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.Host, 443)
	if !HostOK(host) {
		http.Error(w, "devvm proxy: not a host name", http.StatusBadRequest)
		return
	}
	select {
	case s.connects <- struct{}{}:
		defer func() { <-s.connects; s.connectsFull.Store(false) }()
	default:
		s.refuseConnect(w, host, port)
		return
	}
	// One of the VM's links: its socket, before any rule (links.go).
	if l, ok := s.links.find(host, port); ok {
		s.links.connect(w, r, host, port, l)
		return
	}
	if s.links.refuse(w, "CONNECT", host, port) {
		return
	}
	e := Event{Host: host, Port: port, Method: "CONNECT", Agent: r.UserAgent()}
	rule, why, refused := s.egress.checkRefused(r.Context(), host, port, false)
	if why != "" {
		e.Reason, e.Refused = why, refused
		s.block(w, e)
		return
	}
	e.Rule = rule
	if up := s.egress.up.route(host, port, false); up != nil {
		e.Upstream = up.addr
	}
	if s.interceptPorts[port] && s.ca != nil && (s.captures.has(host) || len(s.secrets.forHost(host)) > 0) {
		if s.caEndedRefusal(w, e) {
			return
		}
		client, err := hijack(w)
		if err != nil {
			return
		}
		s.intercept(r.Context(), client, host, port, e)
		return
	}
	s.tunnel(w, r, host, port, e)
}

// refuseConnect refuses a CONNECT past the VM's limit (connects): 503, which a client may try
// again, with the reason, logged as a refused block, as no rule would help. The proxy's own log
// says so the first time the limit is reached since a tunnel last ended, so a VM that keeps
// trying doesn't fill it.
func (s *server) refuseConnect(w http.ResponseWriter, host string, port int) {
	why := strconv.Itoa(cap(s.connects)) + " tunnels open already"
	e := Event{Event: "blocked", Host: host, Port: port, Method: "CONNECT", Refused: true, Reason: why}
	if !s.connectsFull.Swap(true) {
		s.log.Printf("%s:%d: %d tunnels open at once, the VM's limit: refusing more until one ends", host, port, cap(s.connects))
	}
	s.events.record(e)
	w.Header().Set("X-Devvm-Blocked", host)
	http.Error(w, "devvm proxy: "+net.JoinHostPort(host, strconv.Itoa(port))+" is refused: "+e.Reason, http.StatusServiceUnavailable)
}

// tunnel carries a CONNECT to host:port that the policy allows, e its event. The far end's bytes
// go to the client at once, so a protocol whose server speaks first (SMTP) gets its greeting
// before the client sends anything. The client's go on only once they're checked: when they start
// a TLS ClientHello, its SNI must be the host that was checked (which blunts domain fronting), and
// nothing of the client's reaches the far end before that. Other protocols (SSH on :22, …) pass as
// they are.
func (s *server) tunnel(w http.ResponseWriter, r *http.Request, host string, port int, e Event) {
	up, err := s.egress.dialOut(r.Context(), host, port)
	if err != nil {
		s.log.Printf("%s:%d: connect failed: %v", host, port, err)
		e.Reason = reasonConnectFailed
		s.block(w, e)
		return
	}
	defer func() { _ = up.Close() }()
	client, err := hijack(w)
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()
	splice(client, up, func() bool {
		first, sni, isTLS := peekClientHello(client.r)
		if isTLS && !sniMatches(sni, host) {
			e.Event, e.Reason = "blocked", fmt.Sprintf("TLS name %q doesn't match %s", sni, host)
			s.events.record(e)
			return false
		}
		e.Event = "tunnel"
		s.events.record(e)
		_, err := up.Write(first)
		return err == nil
	})
}

func sniMatches(sni, host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return sni == "" || strings.EqualFold(sni, host)
	}
	return strings.EqualFold(strings.TrimSuffix(sni, "."), host)
}

// peekClientHello reads the first TLS record if the stream starts with one, and returns the bytes
// read (to replay upstream), the SNI, and whether it was TLS. It looks at one byte first: only a
// TLS record starts with 0x16, so a client that sends fewer than a record header's five bytes of
// anything else isn't held.
func peekClientHello(r *bufio.Reader) ([]byte, string, bool) {
	if b, err := r.Peek(1); err != nil || b[0] != 0x16 {
		return nil, "", false
	}
	hdr, err := r.Peek(5)
	if err != nil || hdr[1] != 3 {
		return nil, "", false
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	rec := make([]byte, 5+n)
	if _, err := io.ReadFull(r, rec); err != nil {
		return rec, "", true
	}
	return rec, sniOf(rec), true
}

// handleHTTP serves absolute-form requests (plain HTTP, or "GET https://…" from clients like
// busybox wget) and the reserved http://devvm.proxy/ endpoints.
func (s *server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		http.Error(w, "devvm proxy: not a proxy request", http.StatusBadRequest)
		return
	}
	scheme := "http"
	if r.URL.Scheme == "https" {
		scheme = "https"
	}
	def := 80
	if scheme == "https" {
		def = 443
	}
	host, port := splitHostPort(r.URL.Host, def)
	if !HostOK(host) {
		http.Error(w, "devvm proxy: not a host name", http.StatusBadRequest)
		return
	}
	if host == "devvm.proxy" {
		s.serveReserved(w, r)
		return
	}
	// One of the VM's links: its socket, before any rule (links.go). HTTPS to a link goes through
	// CONNECT, so its TLS stays the client's: the proxy makes none of its own to a link.
	if l, ok := s.links.find(host, port); ok {
		if scheme == "https" {
			http.Error(w, "devvm proxy: reach a link over HTTPS through CONNECT", http.StatusBadRequest)
			return
		}
		s.links.forward(w, r, host, port, l)
		return
	}
	if s.links.refuse(w, r.Method, host, port) {
		return
	}
	e := Event{Host: host, Port: port, Method: r.Method, Path: r.URL.Path, Agent: r.UserAgent()}
	if _, why, refused := s.egress.checkRefused(r.Context(), host, port, scheme == "http"); why != "" {
		e.Reason, e.Refused = why, refused
		s.block(w, e)
		return
	}
	// Some clients half-close after sending; don't treat that as the client going away.
	fwd, done := s.forwarder(scheme, r.URL.Host, host, port)
	defer done()
	fwd.ServeHTTP(noCloseNotify{w}, r.WithContext(context.WithoutCancel(r.Context())))
}

type noCloseNotify struct{ http.ResponseWriter }

func (w noCloseNotify) Flush() { _ = http.NewResponseController(w.ResponseWriter).Flush() }

// nothingBlocked is devvm-why's answer when the proxy blocked nothing: a
// DNS or connection error then comes from a tool that skipped the proxy.
const nothingBlocked = "devvm: nothing blocked recently\n" +
	"A DNS or connection error for a host the tier allows means the tool skipped the proxy: turn on its own proxy setting, or give it $HTTPS_PROXY.\n" +
	"https://devvm.dev/docs/using/troubleshooting/#a-host-on-the-allowlist-doesnt-resolve\n"

func (s *server) serveReserved(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/nix/") {
		s.nix.serve(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	switch r.URL.Path {
	case "/blocked":
		rs, _ := s.events.blocked()
		if len(rs) == 0 {
			fmt.Fprint(w, nothingBlocked)
			return
		}
		var b bytes.Buffer
		for _, r := range rs {
			e := r.e
			if e.Refused {
				fmt.Fprintf(&b, "%s  %s %s%s  refused: %s\n", e.Time, e.Method, e.Host, e.Path, e.Reason)
				continue
			}
			fmt.Fprintf(&b, "%s  %s:%d  %s\n    allow on the host: devvm network allow %s\n", e.Time, e.Host, e.Port, e.Reason, ruleFor(e.Host, e.Port))
		}
		_, _ = w.Write(b.Bytes())
	case "/blocked/new":
		rs, count := s.events.blocked()
		fmt.Fprint(w, newBlocks(rs, count, r.URL.Query().Get("after")))
	case "/ca.pem":
		if p := s.ca.pem(); p != nil {
			_, _ = w.Write(p)
			return
		}
		http.Error(w, "devvm proxy: no CA", http.StatusNotFound)
	default:
		http.Error(w, "devvm proxy: unknown endpoint", http.StatusNotFound)
	}
}

func (s *server) handler(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="devvm"`)
		http.Error(w, "devvm proxy: this proxy belongs to another VM", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

// lifelineTick: how often the proxy looks at its VM's lifeline.
const lifelineTick = 3 * time.Second

// lifelineWait bounds how long the proxy waits for its VM's lifeline: it starts before the VM does.
const lifelineWait = 15 * time.Minute

// watchLifeline returns once the VM's lifeline (daemon.Lifeline) no longer holds, or never names a
// process that runs, looking every tick. It follows the start it first sees running, not later
// ones: a restarted VM gets a new proxy. A lifeline a start writes whose process is already gone
// (the VM stopped between two looks) ends it too; what the file held when the proxy started is an
// earlier start's, and waited past.
func watchLifeline(path string, tick time.Duration) {
	if l, ok := daemon.FollowLifeline(path, lifelineWait, tick); ok {
		l.Wait(tick)
	}
}

// IO is what devvm _proxy reads and writes: devvm's own streams.
type IO struct {
	// Stdout gets data: the event log without Config.Log, and what -help prints.
	Stdout io.Writer
	// Stderr gets the proxy's own log lines.
	Stderr io.Writer
	// FS is devvm's own files (its assets), which Config.BuiltinPolicies names paths in.
	FS fs.FS
	// Secret looks a binding's value up, in this process (devvm's secrets' store), for
	// Config.Secrets' bindings: required with them.
	Secret Lookup
	// Capture saves the logins in Config.Captures' replies, in this process (devvm's store of
	// agents' logins): required with them.
	Capture Capturer
}

// Main runs devvm _proxy with args (its flags): the proxy itself, with -config's file, until the
// VM's hostagent is gone. -help prints the flags to std.Stdout. Errors are returned, not printed.
func Main(args []string, std IO) error { return run(args, std, lifelineTick) }

// run is Main, looking at the VM's lifeline every tick.
func run(args []string, std IO, tick time.Duration) error {
	var configPath string
	fs := newFlags(&configPath)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(std.Stdout)
			fs.PrintDefaults()
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	// Without a config, and the password in it, any program on the host could use the proxy, and
	// the VM's tokens with it.
	if configPath == "" {
		return errors.New("-config is required")
	}
	c, err := ReadConfig(configPath)
	if err != nil {
		return err
	}
	if (c.Secrets != "" || c.Upstream != nil && c.Upstream.Secret != "") && std.Secret == nil {
		return errors.New("secrets without a lookup")
	}
	if len(c.Captures) > 0 && std.Capture == nil {
		return errors.New("captures without a capturer")
	}
	return serve(c, std, tick)
}

// serve runs the proxy with c until the VM's hostagent is gone (c.Lifeline).
func serve(c Config, std IO, tick time.Duration) error {
	l := log.New(std.Stderr, "devvm proxy: ", log.LstdFlags)
	if c.ProxyLog != "" {
		f, err := copyRotating(c.ProxyLog, std.Stderr, LogLimit)
		if err != nil {
			return err
		}
		l.SetOutput(f)
	}
	out := std.Stdout
	if c.Log != "" {
		f, err := OpenEventLog(c.Log)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		out = f
	}
	s, err := newServer(c, std, l, out)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", c.Listen) //nolint:noctx // listens for the proxy's whole life
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: http.HandlerFunc(s.handler), ReadHeaderTimeout: 30 * time.Second, MaxHeaderBytes: maxHeaderBytes}
	l.Printf("listening on %s for %s", ln.Addr(), s.vm)
	// What devvm waits for as it starts the proxy: the address it listens on.
	if err := daemon.Ready(ln.Addr().String()); err != nil {
		l.Printf("%v", err)
	}
	if c.Lifeline != "" {
		go func() {
			watchLifeline(c.Lifeline, tick)
			l.Printf("the VM's hostagent is gone; exiting")
			_ = srv.Close()
		}()
	}
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
