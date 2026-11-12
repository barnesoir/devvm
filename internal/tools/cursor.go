package tools

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/devvmhq/devvm/internal/image"
)

// Cursor Agent CLI downloads. mise has no backend that pins Cursor's
// per-platform lab tarballs, so shared-tools/mise.toml holds a version
// hold and http:cursor alias only so the tool is named in [tools]; mise
// lock often omits the entry (no http template), and this writes one with
// each linux platform's archive URL and SHA-256. build.sh fetches them
// (image.CursorAgent / OwnDownload).

const (
	// cursorLab is the install script's download root: …/lab/<version>/<os>/<arch>/agent-cli-package.tar.gz
	cursorLab = "https://downloads.cursor.com/lab/"
	// cursorVersion is the lab package version pinned in shared-tools/mise.toml.
	cursorVersion = "2026.11.11-b912975"
	cursorSHAArm  = "f068af64ed91b5304605976586f690579679f740a41f388091a6b3a2e776987c"
	cursorSHAX64  = "be01f42ad334f81d05a9992fcf060a52cc746f52cc451e849eb652146a6e3c91"
	cursorBackend = "http:cursor"
)

// cursorURL is the lab tarball for a lock platform (linux-arm64, …).
func cursorURL(platform string) (url, sha256 string, ok bool) {
	arch, _ := strings.CutSuffix(strings.TrimPrefix(platform, "linux-"), "-musl")
	var sum string
	switch arch {
	case "arm64":
		sum = cursorSHAArm
	case "x64":
		sum = cursorSHAX64
	default:
		return "", "", false
	}
	// Lab paths use x64/arm64; musl VMs never get this tool (GlibcOnly).
	return cursorLab + cursorVersion + "/linux/" + arch + "/agent-cli-package.tar.gz", sum, true
}

// withCursorDownloads returns the lock with Cursor Agent archives added to
// each OwnDownload cursor entry that lacks them, as withSDKDownloads does
// for dotnet. When mise lock left cursor out (http:cursor has no template),
// it writes the pinned entry first.
func (t Versions) withCursorDownloads(_ context.Context, lock Lock) (Lock, error) {
	for _, d := range image.SharedTools {
		for _, tool := range d.Members {
			if d.Installer != image.CursorAgent {
				continue
			}
			es := slices.Clone(lock.entries(tool))
			if len(es) == 0 {
				es = []lockEntry{{
					"version":    cursorVersion,
					"backend":    cursorBackend,
					"specifiers": []any{cursorVersion},
				}}
			}
			changed := false
			for i, e := range es {
				if hasDownload(e, t.platforms()) {
					continue
				}
				e = maps.Clone(e)
				for _, p := range t.platforms() {
					if url, sum, ok := cursorURL(p); ok {
						e["platforms."+p] = map[string]any{"checksum": "sha256:" + sum, "url": url}
						es[i], changed = e, true
					}
				}
			}
			if !changed {
				continue
			}
			var err error
			if lock, err = lock.withEntries(tool, es); err != nil {
				return Lock{}, err
			}
		}
	}
	return lock, nil
}
