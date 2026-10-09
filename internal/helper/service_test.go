package helper

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nyaaorick/clash-mihomac/internal/netstate/netstatetest"
)

type clients struct {
	mu   sync.Mutex
	dead map[int]bool
}

func (c *clients) kill(pid int) { c.mu.Lock(); c.dead[pid] = true; c.mu.Unlock() }
func (c *clients) alive(pid int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return pid > 0 && !c.dead[pid]
}

// newTestService runs `sleep` as a stand-in core and treats every client
// PID as alive until killed.
func newTestService(t *testing.T) (*Service, *netstatetest.Fake, *clients) {
	t.Helper()
	fake := netstatetest.New()
	cl := &clients{dead: map[int]bool{}}
	s := &Service{
		Root: t.TempDir(), UID: -1, Version: "test", Log: log.New(io.Discard, "", 0),
		Runner: fake,
		Verify: func(string) (string, error) { return "v-test", nil },
		Exec: func(_ string, _ []string, logf *os.File) (*exec.Cmd, error) {
			cmd := exec.Command("/bin/sleep", "60")
			cmd.Stdout, cmd.Stderr = logf, logf
			return cmd, cmd.Start()
		},
		Alive:  cl.alive,
		IsCore: func(int) bool { return true },
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	return s, fake, cl
}

func fakeCore(t *testing.T) *os.File {
	path := filepath.Join(t.TempDir(), "mihomo")
	os.WriteFile(path, []byte("core"), 0o755)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

const testConfig = "secret: 0123456789abcdef0123\nrules: [MATCH,DIRECT]\n"

func call(t *testing.T, s *Service, cmd string, pid int, args any, files ...*os.File) (json.RawMessage, error) {
	t.Helper()
	raw, _ := json.Marshal(args)
	res, err := s.Commands()[cmd](context.Background(), Peer{PID: pid, Files: files}, raw)
	if err != nil {
		return nil, err
	}
	out, _ := json.Marshal(res)
	return out, nil
}

func TestTUNSessionEndsAndRestoresWhenClientDies(t *testing.T) {
	s, fake, cl := newTestService(t)
	res, err := call(t, s, "tun-start", 4242, TUNStartArgs{Instance: "debug", Config: testConfig}, fakeCore(t))
	if err != nil {
		t.Fatal(err)
	}
	var started TUNStartResult
	json.Unmarshal(res, &started)
	if started.CorePID == 0 || started.Version != "v-test" {
		t.Fatalf("started = %+v", started)
	}
	cfg, _ := os.ReadFile(filepath.Join(s.Root, "run", "debug", "runtime.yaml"))
	if !strings.Contains(string(cfg), "device: utun1991") || !strings.Contains(string(cfg), "bind-address: 127.0.0.1") {
		t.Errorf("helper did not enforce config:\n%s", cfg)
	}
	if _, err := os.Stat(s.backupPath()); err != nil {
		t.Fatal("no backup taken")
	}

	// While running, something changes DNS; then the client is kill -9'd.
	fake.Set(func(f *netstatetest.Fake) { f.DNS["Wi-Fi"] = []string{"198.18.0.2"} })
	cl.kill(4242)
	s.Tick(context.Background())

	if len(s.sessions) != 0 {
		t.Fatal("session still active after client died")
	}
	if alive(started.CorePID) {
		t.Error("core still running after client died")
	}
	if got := fake.DNS["Wi-Fi"]; len(got) != 1 || got[0] != "192.168.1.1" {
		t.Errorf("DNS = %v, want restored to 192.168.1.1", got)
	}
	if _, err := os.Stat(s.backupPath()); err == nil {
		t.Error("backup not removed after verified restore")
	}
	last := s.events[len(s.events)-1]
	if !strings.Contains(last.Message, "client pid 4242 exited") || !strings.Contains(last.Message, "restored and verified") {
		t.Errorf("event = %q", last.Message)
	}
}

func TestSysProxyRestoredWhenClientDies(t *testing.T) {
	s, fake, cl := newTestService(t)
	if _, err := call(t, s, "sysproxy-set", 777, InstanceArgs{Instance: "stable"}); err != nil {
		t.Fatal(err)
	}
	if p := fake.Proxies["Wi-Fi|web"]; !p.Enabled || p.Port != 7990 {
		t.Fatalf("web proxy = %+v", p)
	}
	cl.kill(777)
	s.Tick(context.Background())
	for _, k := range []string{"web", "secure", "socks"} {
		if fake.Proxies["Wi-Fi|"+k].Enabled {
			t.Errorf("%s proxy still enabled", k)
		}
	}
	if fake.Bypass["Wi-Fi"] != nil {
		t.Errorf("bypass list = %v, want restored to empty", fake.Bypass["Wi-Fi"])
	}
}

func TestBackupKeptUntilLastSessionEnds(t *testing.T) {
	s, fake, _ := newTestService(t)
	if _, err := call(t, s, "sysproxy-set", 1, InstanceArgs{Instance: "stable"}); err != nil {
		t.Fatal(err)
	}
	if _, err := call(t, s, "tun-start", 2, TUNStartArgs{Instance: "debug", Config: testConfig}, fakeCore(t)); err != nil {
		t.Fatal(err)
	}
	call(t, s, "tun-stop", 2, InstanceArgs{Instance: "debug"})
	if !fake.Proxies["Wi-Fi|web"].Enabled {
		t.Error("ending one session undid another session's system proxy")
	}
	call(t, s, "sysproxy-clear", 1, InstanceArgs{Instance: "stable"})
	if fake.Proxies["Wi-Fi|web"].Enabled {
		t.Error("system proxy not restored after last session")
	}
}

func TestRecoverRestoresLeftoverBackup(t *testing.T) {
	s, fake, _ := newTestService(t)
	if err := s.ensureBackup(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash: settings changed, helper gone, backup left behind.
	fake.Set(func(f *netstatetest.Fake) { f.DNS["Wi-Fi"] = []string{"198.18.0.2"} })

	s.Recover(context.Background())
	if got := fake.DNS["Wi-Fi"]; len(got) != 1 || got[0] != "192.168.1.1" {
		t.Errorf("DNS = %v after recovery", got)
	}
	if _, err := os.Stat(s.backupPath()); err == nil {
		t.Error("backup not removed")
	}
}

func TestTUNRoutesRecovery(t *testing.T) {
	s, fake, _ := newTestService(t)
	res, err := call(t, s, "tun-start", 9, TUNStartArgs{Instance: "debug", Config: testConfig}, fakeCore(t))
	if err != nil {
		t.Fatal(err)
	}
	var started TUNStartResult
	json.Unmarshal(res, &started)

	// No routes on utun1991 (fake netstat is empty): after two checks the
	// core is restarted.
	for i := 0; i < 6; i++ {
		s.Tick(context.Background())
	}
	if s.sessions["debug"].CorePID == started.CorePID {
		t.Error("core not restarted after its routes disappeared")
	}

	fake.Set(func(f *netstatetest.Fake) {
		f.Routes = "Destination Gateway Flags Netif\n1 198.18.0.1 UGSc utun1991\n"
	})
	pid := s.sessions["debug"].CorePID
	for i := 0; i < 6; i++ {
		s.Tick(context.Background())
	}
	if s.sessions["debug"].CorePID != pid {
		t.Error("core restarted even though routes are present")
	}
}

func TestTUNStartRejects(t *testing.T) {
	s, _, _ := newTestService(t)
	core := fakeCore(t)
	cases := map[string]struct {
		pid   int
		args  TUNStartArgs
		files []*os.File
	}{
		"unknown instance": {1, TUNStartArgs{Instance: "../etc", Config: testConfig}, []*os.File{core}},
		"no peer pid":      {0, TUNStartArgs{Instance: "debug", Config: testConfig}, []*os.File{core}},
		"weak secret":      {1, TUNStartArgs{Instance: "debug", Config: "secret: x\n"}, []*os.File{core}},
		"no core file":     {1, TUNStartArgs{Instance: "debug", Config: testConfig}, nil},
		"two files":        {1, TUNStartArgs{Instance: "debug", Config: testConfig}, []*os.File{core, core}},
	}
	for name, c := range cases {
		if _, err := call(t, s, "tun-start", c.pid, c.args, c.files...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// An earlier case installed a verified core before rejecting its config.
	os.Remove(filepath.Join(s.Root, "run", "debug", "mihomo"))
	s.Verify = func(string) (string, error) { return "", os.ErrPermission }
	if _, err := call(t, s, "tun-start", 1, TUNStartArgs{Instance: "debug", Config: testConfig}, core); err == nil {
		t.Error("unverified core accepted")
	}
	if _, err := os.Stat(filepath.Join(s.Root, "run", "debug", "mihomo")); err == nil {
		t.Error("unverified core left in place")
	}
}
