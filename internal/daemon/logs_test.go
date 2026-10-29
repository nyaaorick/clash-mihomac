package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nyaaorick/clash-mihomac/internal/gui"
	"github.com/nyaaorick/clash-mihomac/internal/verge"
)

func TestReadLogTailsAndCaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	if lines, err := ReadLog(path, 10); err != nil || len(lines) != 0 {
		t.Fatalf("missing log: %v, %v", lines, err)
	}
	var b strings.Builder
	for i := 0; i < 500; i++ {
		b.WriteString(strings.Repeat("x", 1000) + "\n")
	}
	b.WriteString("last\n")
	os.WriteFile(path, []byte(b.String()), 0o600)
	lines, err := ReadLog(path, 3)
	if err != nil || len(lines) != 3 || lines[2] != "last" {
		t.Fatalf("tail = %d lines, %v", len(lines), err)
	}
	// Only the end of a large file is read, and the half line at the cut is dropped.
	lines, _ = ReadLog(path, 2000)
	if len(lines) == 0 || len(lines) >= 500 || lines[0] != strings.Repeat("x", 1000) {
		t.Errorf("capped read: %d lines, first %q", len(lines), lines[0][:min(10, len(lines[0]))])
	}
}

func TestLogsAreFullScopeOnlyAndNameSources(t *testing.T) {
	home := t.TempDir()
	vd := verge.Dir(t.TempDir())
	os.MkdirAll(vd.Path("logs"), 0o700)
	os.WriteFile(vd.Path("logs", "latest.log"), []byte("verge line\n"), 0o600)
	os.WriteFile(filepath.Join(home, DaemonLog), []byte("daemon line\n"), 0o600)
	d := &Daemon{home: home, o: Options{Verge: vd}}
	h := gui.Handler("127.0.0.1:1", gui.Tokens{Full: strings.Repeat("f", 32), Agent: strings.Repeat("a", 32)}, d.api())

	get := func(token, source string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1/api/logs?source="+source, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var body map[string]any
		json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}
	if code, _ := get(strings.Repeat("a", 32), "daemon"); code != http.StatusForbidden {
		t.Errorf("agent got %d", code)
	}
	code, body := get(strings.Repeat("f", 32), "daemon")
	if code != http.StatusOK || body["lines"].([]any)[0] != "daemon line" {
		t.Errorf("daemon log: %d %v", code, body)
	}
	code, body = get(strings.Repeat("f", 32), "verge")
	if code != http.StatusOK || body["lines"].([]any)[0] != "verge line" {
		t.Errorf("verge log: %d %v", code, body)
	}
	if code, _ := get(strings.Repeat("f", 32), "core"); code != http.StatusBadRequest {
		t.Errorf("unknown source got %d", code)
	}
}
