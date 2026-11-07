package netpolicy

import (
	"net/netip"
	"slices"
	"strings"
)

// Risk is why devvm network lock marks a learned host, which starts
// unticked: each is an easy way to send data out. "" for none.
type Risk string

// The risks, as devvm network lock --json names them.
const (
	RiskAddress   Risk = "address"   // an address, not a name
	RiskLookalike Risk = "lookalike" // a punycode label (xn--), which can look like another name
	RiskPaste     Risk = "paste"     // a paste or file drop site
	RiskStorage   Risk = "storage"   // file storage or file sharing
	RiskTunnel    Risk = "tunnel"    // a tunnel to someone's own machine
	RiskWebhook   Risk = "webhook"   // a service that records what it's sent
	RiskHosting   Risk = "hosting"   // free hosting, where anyone runs their own server
	RiskChat      Risk = "chat"      // a chat service's endpoint for bots and webhooks
)

// riskyHosts are the hosts devvm network lock marks, each matched as
// itself and as any of its subdomains, by why: well known ones of each
// kind, as the docs list their kinds. devvm's own rules leave them out
// (layers/base.policy), and RiskOf adds the patterns a list can't hold.
func riskyHosts() map[Risk][]string {
	return map[Risk][]string{
		RiskPaste: {
			"pastebin.com", "paste.ee", "hastebin.com", "termbin.com", "dpaste.org", "paste.rs", "rentry.co", "ghostbin.site",
			"gist.githubusercontent.com", "gist.github.com", "gofile.io", "pixeldrain.com", "bashupload.com", "uguu.se",
			"filebin.net", "ix.io", "sprunge.us", "bpa.st", "controlc.com", "justpaste.it",
		},
		RiskStorage: {
			"transfer.sh", "file.io", "0x0.st", "temp.sh", "catbox.moe", "wetransfer.com", "mega.nz", "dropbox.com",
			"dropboxusercontent.com", "drive.google.com", "storage.googleapis.com", "firebasestorage.googleapis.com",
			"blob.core.windows.net", "file.core.windows.net", "dfs.core.windows.net", "web.core.windows.net",
			"r2.cloudflarestorage.com", "s3.amazonaws.com", "backblazeb2.com", "digitaloceanspaces.com", "wasabisys.com",
			"linodeobjects.com", "onedrive.live.com", "1drv.ms", "sharepoint.com", "box.com",
		},
		RiskTunnel:  {"ngrok.io", "ngrok.app", "ngrok-free.app", "ngrok.dev", "ngrok-free.dev", "trycloudflare.com", "loca.lt", "serveo.net"},
		RiskWebhook: {"webhook.site", "pipedream.net", "requestcatcher.com", "beeceptor.com", "interact.sh", "burpcollaborator.net"},
		RiskHosting: {
			"r2.dev", "workers.dev", "pages.dev", "vercel.app", "netlify.app", "herokuapp.com", "glitch.me", "repl.co",
			"cloudfront.net", "on.aws", "firebaseio.com", "supabase.co",
		},
		RiskChat: {"discord.com", "discordapp.com", "hooks.slack.com", "api.telegram.org", "script.google.com"},
	}
}

// RiskOf returns why host is risky to allow (Risk): an address; a name
// with a punycode label; a host of riskyHosts or under one; an OAST
// domain (oast.fun, oast.pro and the rest); one of S3's regional hosts,
// AWS's or AWS China's (bucket.s3.us-east-1.amazonaws.com); or an API
// Gateway endpoint (id.execute-api.us-east-1.amazonaws.com). "" for any
// other.
func RiskOf(host string) Risk {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return RiskAddress
	}
	labels := strings.Split(host, ".")
	if slices.ContainsFunc(labels, func(l string) bool { return strings.HasPrefix(l, "xn--") }) {
		return RiskLookalike
	}
	for why, hosts := range riskyHosts() {
		if slices.ContainsFunc(hosts, func(h string) bool { return host == h || strings.HasSuffix(host, "."+h) }) {
			return why
		}
	}
	n := len(labels)
	aws := strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".amazonaws.com.cn")
	switch {
	case n >= 2 && labels[n-2] == "oast":
		return RiskWebhook
	case aws && slices.ContainsFunc(labels, func(l string) bool { return l == "s3" || strings.HasPrefix(l, "s3-") }):
		return RiskStorage
	case aws && slices.Contains(labels, "execute-api"):
		return RiskHosting
	}
	return ""
}

// secondLevels are the labels under a two-letter country's domain that
// countries give out names under, as co.uk and com.au are: Domain takes
// three labels for them. A short list, not the Public Suffix List, which
// devvm would have to ship and keep current: a name it misses only starts
// unticked.
func secondLevels() []string {
	return []string{"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "nic"}
}

// Domain is host's registrable domain, as devvm network lock compares
// hosts by: its last two labels, or three under a country's second level
// (example.co.uk, secondLevels); an address, or a name of two labels or
// fewer, is itself.
func Domain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return host
	}
	labels := strings.Split(host, ".")
	n, keep := len(labels), 2
	if n >= 3 && len(labels[n-1]) == 2 && slices.Contains(secondLevels(), labels[n-2]) {
		keep = 3
	}
	if n <= keep {
		return host
	}
	return strings.Join(labels[n-keep:], ".")
}
