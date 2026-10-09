package daemon

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/nyaaorick/clash-mihomac/internal/instance"
)

func TestListInstancesIncludesProfiles(t *testing.T) {
	home := t.TempDir()
	p, err := instance.Create(home, "work")
	if err != nil {
		t.Fatal(err)
	}
	list, err := ListInstances(home, "debug")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, i := range list {
		names = append(names, i.Name)
		if i.Running {
			t.Errorf("%s reported running", i.Name)
		}
		if i.Name == "debug" && !i.Current {
			t.Error("current instance not marked")
		}
		if i.Name == p.Name && (!i.Profile || i.Label != "work" || i.MixedPort != p.MixedPort) {
			t.Errorf("profile row = %+v", i)
		}
	}
	if got := strings.Join(names, ","); got != "debug,stable,p1" {
		t.Errorf("names = %s", got)
	}
}

func TestReadLogTailsAndCaps(t *testing.T) {
	home := t.TempDir()
	inst, _ := instance.Get(home, "debug")
	os.MkdirAll(inst.Dir, 0o700)
	var b strings.Builder
	for i := 0; i < 50000; i++ {
		b.WriteString("line of log output number x\n")
	}
	os.WriteFile(inst.Path("daemon.log"), []byte(b.String()), 0o600)

	lines, err := ReadLog(inst, "daemon", 3)
	if err != nil || len(lines) != 3 || lines[2] != "line of log output number x" {
		t.Errorf("ReadLog = %q, %v", lines, err)
	}
	all, _ := ReadLog(inst, "daemon", 2000)
	if len(all) != 2000 {
		t.Errorf("got %d lines", len(all))
	}
	if lines, err := ReadLog(inst, "core", 10); err != nil || len(lines) != 0 {
		t.Errorf("missing log = %q, %v", lines, err)
	}
	if _, err := ReadLog(inst, "../etc/passwd", 10); err == nil {
		t.Error("arbitrary log source accepted")
	}
}

func TestLogsAreFullScopeOnly(t *testing.T) {
	t.Setenv("MIHOMAC_HOME", t.TempDir())
	d := &Daemon{inst: instance.Instance{Name: "debug"}}
	req := httptest.NewRequest(http.MethodGet, "/api/logs", nil)
	rec := httptest.NewRecorder()
	d.handleLogs(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("no scope: status %d", rec.Code)
	}
}
