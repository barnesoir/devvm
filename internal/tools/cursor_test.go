package tools

import (
	"strings"
	"testing"
)

func TestWithCursorDownloads(t *testing.T) {
	e := newEnv(t)
	// mise lock often omits http:cursor; withCursorDownloads must still pin it.
	lock, err := e.withCursorDownloads(t.Context(), parsed(t, []byte("")))
	if err != nil {
		t.Fatal(err)
	}
	if lock.Version("cursor") != cursorVersion || lock.Backend("cursor") != cursorBackend {
		t.Errorf("cursor = %s %s", lock.Version("cursor"), lock.Backend("cursor"))
	}
	if !lock.HasDownload("cursor", e.platforms()) {
		t.Errorf("cursor lacks downloads: %s", lock.Bytes())
	}
	url, sum := lock.Download("cursor", "linux-arm64")
	if !strings.Contains(url, cursorVersion+"/linux/arm64/") || sum != "sha256:"+cursorSHAArm {
		t.Errorf("arm64 = %s %s", url, sum)
	}
	again, err := e.withCursorDownloads(t.Context(), lock)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Bytes()) != string(lock.Bytes()) {
		t.Errorf("a second pass changed the lock")
	}
}

func TestCursorURL(t *testing.T) {
	for platform, arch := range map[string]string{
		"linux-arm64": "arm64", "linux-arm64-musl": "arm64",
		"linux-x64": "x64", "linux-x64-musl": "x64",
	} {
		url, sum, ok := cursorURL(platform)
		if !ok || !strings.Contains(url, "/linux/"+arch+"/") || sum == "" {
			t.Errorf("cursorURL(%s) = %s %s %v", platform, url, sum, ok)
		}
	}
	if _, _, ok := cursorURL("darwin-arm64"); ok {
		t.Error("darwin got a URL")
	}
}
