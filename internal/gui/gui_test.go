package gui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const addr = "127.0.0.1:19991"

var tok = Tokens{
	Full:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	Agent: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
}

// echoAPI reports the scope it saw.
var echoAPI = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"scope":"` + ScopeFrom(r.Context()) + `"}`))
})

func serve(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler(addr, tok, echoAPI).ServeHTTP(rec, req)
	return rec
}

func newReq(method, target, token string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Host = addr
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if method != http.MethodGet {
		req.Header.Set("X-Mihomac", "1")
	}
	return req
}

func TestRejectsForeignHost(t *testing.T) {
	req := newReq(http.MethodGet, "/api/status", tok.Full)
	req.Host = "evil.example:19991"
	if rec := serve(t, req); rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestRequiresToken(t *testing.T) {
	for _, path := range []string{"/", "/api/status", "/app.js"} {
		if rec := serve(t, newReq(http.MethodGet, path, "")); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", path, rec.Code)
		}
	}
	if rec := serve(t, newReq(http.MethodGet, "/api/status", "wrong")); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong bearer: status = %d, want 401", rec.Code)
	}
}

func TestTokenQueryBecomesCookie(t *testing.T) {
	rec := serve(t, newReq(http.MethodGet, "/?token="+tok.Full, ""))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie = %+v", cookies)
	}
	req := newReq(http.MethodGet, "/", "")
	req.AddCookie(cookies[0])
	if rec := serve(t, req); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Clash Mihomac") {
		t.Errorf("dashboard: status = %d", rec.Code)
	}
	if rec := serve(t, newReq(http.MethodGet, "/?token="+tok.Agent, "")); rec.Code != http.StatusUnauthorized {
		t.Errorf("agent token must not unlock the GUI: status = %d", rec.Code)
	}
}

func TestScopes(t *testing.T) {
	cases := []struct {
		name, method, path, token string
		want                      int
		scope                     string
	}{
		{"full read", "GET", "/api/status", tok.Full, 200, ScopeFull},
		{"agent read", "GET", "/api/connections", tok.Agent, 200, ScopeAgent},
		{"agent propose", "POST", "/api/proposals", tok.Agent, 200, ScopeAgent},
		{"agent probe", "POST", "/api/probe", tok.Agent, 200, ScopeAgent},
		{"agent apply", "POST", "/api/proposals/abc/apply", tok.Agent, 403, ""},
		{"agent direct change", "POST", "/api/rules/change", tok.Agent, 403, ""},
		{"agent mode switch", "POST", "/api/mode", tok.Agent, 403, ""},
		{"full apply", "POST", "/api/proposals/abc/apply", tok.Full, 200, ScopeFull},
	}
	for _, c := range cases {
		rec := serve(t, newReq(c.method, c.path, c.token))
		if rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d", c.name, rec.Code, c.want)
			continue
		}
		if c.scope != "" && !strings.Contains(rec.Body.String(), `"scope":"`+c.scope+`"`) {
			t.Errorf("%s: body = %s", c.name, rec.Body)
		}
	}
}

func TestPostNeedsCSRFHeader(t *testing.T) {
	req := newReq(http.MethodPost, "/api/mode", tok.Full)
	req.Header.Del("X-Mihomac")
	if rec := serve(t, req); rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestLoadOrCreateToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gui-token")
	a, err := LoadOrCreateToken(path)
	if err != nil || len(a) != 64 {
		t.Fatalf("token = %q, %v", a, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	b, err := LoadOrCreateToken(path)
	if err != nil || a != b {
		t.Errorf("token not reused: %q vs %q, %v", a, b, err)
	}
}
