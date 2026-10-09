// Package gui serves the localhost dashboard and guards the daemon's API.
//
// The daemon only ever listens on 127.0.0.1. Every request must carry one
// of the instance's tokens, and requests whose Host header isn't the
// loopback address are rejected to block DNS-rebinding attacks from web
// pages. There are two tokens:
//
//   - the full token (gui-token) is for the person: the browser GUI and CLI
//   - the agent token (mcp-token) is for AI assistants via MCP: it can read
//     everything and create rule-change proposals, but never apply them
//
// State-changing requests must also send "X-Mihomac: 1". Browsers can't
// add that header cross-origin without a CORS preflight, which this server
// never approves, so another site can't drive the API even with cookies.
package gui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
)

//go:embed static
var static embed.FS

// Cookies are shared across ports on 127.0.0.1, so each instance's cookie is
// named after its port; otherwise opening one instance's GUI would log you
// out of another's.
const cookieBase = "mihomac_token"

// Scopes a token can carry.
const (
	ScopeFull  = "full"
	ScopeAgent = "agent"
)

// Tokens are an instance's credentials.
type Tokens struct {
	Full  string
	Agent string
}

type scopeKey struct{}

// ScopeFrom returns the scope of the request's token.
func ScopeFrom(ctx context.Context) string {
	s, _ := ctx.Value(scopeKey{}).(string)
	return s
}

// LoadOrCreateToken reads the token at path, creating a random one if the
// file doesn't exist. The file is readable only by its owner.
func LoadOrCreateToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if tok := strings.TrimSpace(string(data)); len(tok) >= 32 {
			return tok, nil
		}
		return "", fmt.Errorf("token file %s is too short; delete it to regenerate", path)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

// Handler serves the dashboard and api for a server listening on addr
// (host:port).
func Handler(addr string, tok Tokens, api http.Handler) http.Handler {
	assets, err := fs.Sub(static, "static")
	if err != nil {
		panic(err)
	}
	files := http.FileServerFS(assets)
	mux := http.NewServeMux()
	mux.Handle("/api/", api)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		files.ServeHTTP(w, r)
	})
	return guard(addr, tok, mux)
}

func guard(addr string, tok Tokens, next http.Handler) http.Handler {
	_, port, _ := net.SplitHostPort(addr)
	allowedHosts := map[string]bool{"127.0.0.1:" + port: true, "localhost:" + port: true}
	cookieName := cookieBase + "_" + port

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedHosts[r.Host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")

		// The URL printed by the CLI carries the full token once; trade it
		// for a cookie and drop it from the address bar.
		if q := r.URL.Query().Get("token"); q != "" && r.URL.Path == "/" {
			if !equal(q, tok.Full) {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name: cookieName, Value: tok.Full, Path: "/",
				HttpOnly: true, SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		scope := scopeOf(r, tok, cookieName)
		if scope == "" {
			http.Error(w, "unauthorized: open the URL printed by `mihomac status`", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-Mihomac") != "1" {
				http.Error(w, "missing X-Mihomac header", http.StatusForbidden)
				return
			}
			if scope == ScopeAgent && !(r.Method == http.MethodPost && (r.URL.Path == "/api/proposals" || r.URL.Path == "/api/probe")) {
				http.Error(w, "agents may only read and propose changes", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), scopeKey{}, scope)))
	})
}

func scopeOf(r *http.Request, tok Tokens, cookieName string) string {
	var presented string
	if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		presented = bearer
	} else if c, err := r.Cookie(cookieName); err == nil {
		presented = c.Value
	}
	switch {
	case presented == "":
		return ""
	case equal(presented, tok.Full):
		return ScopeFull
	case tok.Agent != "" && equal(presented, tok.Agent):
		return ScopeAgent
	}
	return ""
}

func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
