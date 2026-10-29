package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/nyaaorick/clash-mihomac/internal/verge"
)

// Verge's default controller is a Unix socket; make sure the client
// reaches one and sends the secret.
func TestControllerOverUnixSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "m.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sec" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"version": "unix-1"})
	})}
	go srv.Serve(ln)
	defer srv.Close()

	c := newController(verge.Endpoint{Network: "unix", Address: sock, Secret: "sec"})
	v, err := c.version(context.Background())
	if err != nil || v != "unix-1" {
		t.Fatalf("version = %q, %v", v, err)
	}
	c.set(verge.Endpoint{Network: "unix", Address: sock, Secret: "wrong"})
	if _, err := c.version(context.Background()); err == nil {
		t.Error("wrong secret accepted")
	}
	var herr *ctrlHTTPError
	if _, err := c.version(context.Background()); !errors.As(err, &herr) || herr.Status != http.StatusUnauthorized {
		t.Errorf("want typed HTTP error, got %v", err)
	}
	c.set(verge.Endpoint{Network: "unix", Address: filepath.Join(t.TempDir(), "none.sock"), Secret: "sec"})
	if _, err := c.version(context.Background()); err == nil || errors.As(err, &herr) {
		t.Errorf("a missing socket must be a transport error, got %v", err)
	}
	if !c.ready() {
		t.Error("controller with an endpoint must report ready")
	}
	if (&controller{}).ready() {
		t.Error("empty controller must not report ready")
	}
}
