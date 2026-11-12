package agentlogin

// Cursor Agent CLI's browser login, as devvm keeps it: the store's
// .config/cursor-agent/auth.json (a File of kind Cursor).
//
// Formats (checked against Cursor Agent CLI 2026.09.18 / install package
// 2026.11.11): `agent login` opens {websiteUrl}/loginDeepControl with a
// PKCE challenge and uuid (default website https://cursor.com), then polls
// GET {apiUrl}/auth/poll?uuid=&verifier= (default API https://api2.cursor.sh)
// until the reply is JSON with accessToken and refreshToken. On Linux the
// CLI writes ~/.config/cursor-agent/auth.json mode 600 as
// {accessToken, refreshToken, apiKey?, bedrockCredentials?}. Later requests
// send Authorization: Bearer <accessToken> to api2.cursor.sh, api3, and the
// api5 agent endpoint (*.api5.cursor.sh). There is no localhost callback, so
// OwnLogin needs no port forward.
// Host-side refresh of browser tokens is not a documented public REST
// endpoint in that CLI; get returns the access token while its JWT is still
// valid (refreshMargin), else RefreshError asking for login again. The
// refreshToken is kept on the host for a later refresh path.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/devvmhq/devvm/internal/agents"
	"github.com/devvmhq/devvm/internal/proxy"
)

const (
	// CursorAPIHost is where Cursor Agent CLI sends its access token.
	CursorAPIHost = "api2.cursor.sh"
	// CursorPollPath is the browser-login poll path on CursorAPIHost.
	CursorPollPath = "/auth/poll"
	// CursorAuthName is the login binding's name: the file's kind.
	CursorAuthName = agents.Cursor
)

// ErrCursorNoLogin is Get's error when the store has no Cursor Agent login.
var ErrCursorNoLogin = errors.New("there's no Cursor Agent login")

func cursorPlaceholder(salt string) string {
	return Placeholder("", agents.Cursor, salt)
}

func cursorBindings(m map[string]any, salt string) []proxy.Binding {
	if str(m, "accessToken") == "" {
		return nil
	}
	return login(agents.Cursor, CursorAuthName, authorization(
		CursorAPIHost, "api2direct.cursor.sh", "api3.cursor.sh", "*.api5.cursor.sh",
	), cursorPlaceholder(salt))
}

// cursorVM is the VM's auth.json: placeholders for access and refresh tokens,
// no apiKey, and none of the store's other fields.
func cursorVM(m map[string]any, salt string) map[string]any {
	if str(m, "accessToken") == "" {
		return map[string]any{}
	}
	return map[string]any{
		"accessToken":  cursorPlaceholder(salt),
		"refreshToken": managed,
	}
}

// cursorGet is the access token while its JWT is still valid; otherwise a
// RefreshError asking to log in again (no public browser-token refresh URL yet).
func (f File) cursorGet(ctx context.Context, name string) (string, error) {
	_ = ctx
	if name != CursorAuthName {
		return "", fmt.Errorf("no Cursor Agent login %q", name)
	}
	unlock, err := lockLogin(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrCursorNoLogin
	} else if err != nil {
		return "", err
	}
	defer unlock()
	m, err := readJSON(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrCursorNoLogin
	} else if err != nil {
		return "", err
	}
	at := str(m, "accessToken")
	if at == "" {
		return "", ErrCursorNoLogin
	}
	if cursorTokenFresh(at) {
		return at, nil
	}
	return "", &RefreshError{Agent: agents.Cursor, Err: errors.New("the access token is expired; Cursor Agent browser-token refresh isn't wired yet")}
}

// cursorTokenFresh reports whether tok is a JWT whose exp is more than
// refreshMargin away, or a non-JWT token (treated as still usable).
func cursorTokenFresh(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return true
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp == 0 {
		return true
	}
	return time.Until(time.Unix(claims.Exp, 0)) > refreshMargin
}

// cursorCapture saves a successful /auth/poll reply in m and returns the VM's
// placeholder reply (camelCase, as the CLI expects).
func cursorCapture(_ map[string]any, reply []byte, salt string) (map[string]any, map[string]any, error) {
	var r map[string]any
	if json.Unmarshal(reply, &r) != nil || r == nil {
		return nil, nil, errors.New("the reply isn't a JSON object")
	}
	at, rt := str(r, "accessToken"), str(r, "refreshToken")
	if at == "" || rt == "" {
		return nil, nil, errNoLogin
	}
	out := map[string]any{"accessToken": at, "refreshToken": rt}
	if v, ok := r["apiKey"]; ok {
		out["apiKey"] = v
	}
	vm := map[string]any{
		"accessToken":  cursorPlaceholder(salt),
		"refreshToken": managed,
	}
	return out, vm, nil
}
