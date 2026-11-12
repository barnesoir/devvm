package agentlogin

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// Cursor Agent's browser login: GET /auth/poll's camelCase reply is saved as
// auth.json; the VM gets placeholders only; Authorization is bound for the
// Cursor API hosts. Get returns the access token while its JWT is fresh.
func TestCursorCapture(t *testing.T) {
	f := storeFile(t, Cursor, "auth.json")
	at := jwtWith(time.Now().Add(time.Hour), nil)
	rt := "rt-cursor-real"
	out, err := f.Capture("", nil, reply(map[string]any{
		"accessToken": at, "refreshToken": rt, "apiKey": "ak-should-keep",
	}))
	must(t, err)
	for _, s := range []string{at, rt, "ak-should-keep"} {
		if strings.Contains(string(out), s) {
			t.Errorf("the VM's reply holds %q: %s", s, out)
		}
	}
	m := readStore(t, f)
	if str(m, "accessToken") != at || str(m, "refreshToken") != rt || str(m, "apiKey") != "ak-should-keep" {
		t.Errorf("the store's login = %v", m)
	}
	ph := cursorPlaceholder(salt)
	var vm map[string]any
	must(t, json.Unmarshal(out, &vm))
	if vm["accessToken"] != ph || vm["refreshToken"] != managed || len(vm) != 2 {
		t.Errorf("the VM's reply = %v", vm)
	}
	bs := bindings(t, f)
	if len(bs) != 1 || bs[0].Name != CursorAuthName || bs[0].Placeholder != ph || bs[0].Header != "Authorization" ||
		!slices.Equal(bs[0].Hosts, []string{"api2.cursor.sh", "api2direct.cursor.sh", "api3.cursor.sh", "*.api5.cursor.sh"}) {
		t.Errorf("bindings = %+v", bs)
	}
	data, _ := vmCopy(t, f)
	if strings.Contains(data, "real") || strings.Contains(data, at) || !strings.Contains(data, ph) ||
		!strings.Contains(data, `"refreshToken": "`+managed+`"`) {
		t.Errorf("the VM's copy = %s", data)
	}
	if b, answer, err := f.CaptureRequest("", nil); err != nil || string(b) != "" || answer != nil {
		t.Errorf("CaptureRequest: %q, %s, %v", b, answer, err)
	}
	if _, err := f.Capture("", nil, reply(map[string]any{"accessToken": at})); err == nil {
		t.Error("a reply without refreshToken was saved")
	}
	must(t, f.Remove())
	if _, err := os.Stat(f.Path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("after Remove: %v", err)
	}
	if bs := bindings(t, File{Kind: Cursor, Path: writeFile(t, map[string]any{})}); len(bs) != 0 {
		t.Errorf("bindings with no login = %+v", bs)
	}
}

//nolint:gosec // a test's fake tokens
func TestCursorGet(t *testing.T) {
	fresh := jwtWith(time.Now().Add(time.Hour), nil)
	f := File{Kind: Cursor, Path: writeFile(t, map[string]any{
		"accessToken": fresh, "refreshToken": "rt-cursor",
	})}
	v, err := f.Get(t.Context(), CursorAuthName)
	if err != nil || v != fresh {
		t.Fatalf("value = %q, %v", v, err)
	}
	if _, err := f.Get(t.Context(), "other"); err == nil {
		t.Error("another name looked up")
	}
	expired := jwtWith(time.Now().Add(-time.Minute), nil)
	bad := File{Kind: Cursor, Path: writeFile(t, map[string]any{
		"accessToken": expired, "refreshToken": "rt-cursor",
	})}
	var re *RefreshError
	if _, err := bad.Get(t.Context(), CursorAuthName); !errors.As(err, &re) || re.Agent != Cursor {
		t.Errorf("an expired token: %v", err)
	}
	none := File{Kind: Cursor, Path: writeFile(t, map[string]any{})}
	if _, err := none.Get(t.Context(), CursorAuthName); !errors.Is(err, ErrCursorNoLogin) {
		t.Errorf("no login: %v", err)
	}
}
