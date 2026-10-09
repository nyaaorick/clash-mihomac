package daemon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/gui"
	"github.com/nyaaorick/clash-mihomac/internal/health"
	"github.com/nyaaorick/clash-mihomac/internal/instance"
	"github.com/nyaaorick/clash-mihomac/internal/traffic"
	"github.com/nyaaorick/clash-mihomac/internal/vps"
)

const (
	testAddr      = "127.0.0.1:19991"
	fullToken     = "0123456789abcdef0123456789abcdef0123456789abcdef"
	agentToken    = "fedcba9876543210fedcba9876543210fedcba9876543210"
	testPassword  = "correct-horse-battery-staple"
	testChecksum  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	preflightText = `@@uid
0
@@os
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
ID=debian
@@arch
x86_64
@@systemd
yes
@@listen
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
@@ntp
yes
@@mem
1024
@@disk
10000
@@cc
reno cubic bbr
cubic
@@firewall
ufw
@@pkg
apt-get
@@end
`
)

// vpsEnv is a daemon wired to a scripted server and a fake mihomo controller.
type vpsEnv struct {
	d       *Daemon
	srv     *vps.FakeServer
	h       http.Handler
	home    string
	reloads int
}

func newVPSEnv(t *testing.T) *vpsEnv {
	t.Helper()
	home := t.TempDir()
	t.Setenv("MIHOMAC_HOME", home)
	env := &vpsEnv{home: home}

	ctrl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/configs":
			env.reloads++
		case strings.HasSuffix(r.URL.Path, "/delay"):
			json.NewEncoder(w).Encode(map[string]int{"delay": 123})
		case r.URL.Path == "/rules":
			w.Write([]byte(`{"rules":[]}`))
		}
	}))
	t.Cleanup(ctrl.Close)

	inst, _ := instance.Get(home, "debug")
	os.MkdirAll(inst.Dir, 0o700)
	cfg := filepath.Join(home, "config.yaml")
	os.WriteFile(cfg, []byte("proxies: []\nrules: []\n"), 0o600)
	env.srv = &vps.FakeServer{Handlers: []vps.FakeHandler{
		vps.Reply("@@uid", preflightText, 0),
		vps.Reply("systemctl is-active sing-box", "active\n", 0),
		vps.Reply("ss -ltn", "listening\n", 0),
		vps.Reply("version | head -1", "sing-box version 1.12.0\n", 0),
		vps.Reply("api.ipify.org", "203.0.113.5\n", 0),
		vps.Reply("getent hosts", "93.184.216.34 example.com\n", 0),
	}}
	d := &Daemon{
		o: Options{ConfigPath: cfg}, inst: inst, mode: "port-only",
		ctrl:      controller{addr: strings.TrimPrefix(ctrl.URL, "http://"), secret: "s"},
		health:    health.LoadHistory(inst.Path("health.json")),
		tracker:   NewTracker(),
		proposals: LoadProposals(inst.Path("proposals.json")),
	}
	d.traffic = &trafficState{store: traffic.OpenStore("", time.Hour), seenOnce: map[string]int{}, addrs: map[string]nodeAddrEntry{}}
	d.initVPS()
	d.vps.dialer = env.srv
	env.d = d
	env.h = gui.Handler(testAddr, gui.Tokens{Full: fullToken, Agent: agentToken}, d.api())
	return env
}

func (e *vpsEnv) call(t *testing.T, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var r *bytes.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		r = bytes.NewReader(data)
	} else {
		r = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = testAddr
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Mihomac", "1")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (e *vpsEnv) post(t *testing.T, path string, body, out any) int {
	t.Helper()
	code, data := e.call(t, http.MethodPost, path, fullToken, body)
	if out != nil && code == http.StatusOK {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("%s: %v: %s", path, err, data)
		}
	}
	return code
}

func (e *vpsEnv) waitJob(t *testing.T, id string) *vpsJob {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		code, data := e.call(t, http.MethodGet, "/api/vps/jobs/"+id, fullToken, nil)
		if code != http.StatusOK {
			t.Fatalf("job status %d: %s", code, data)
		}
		var j vpsJob
		json.Unmarshal(data, &j)
		if j.Done {
			return &j
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return nil
}

func TestSetupEndToEnd(t *testing.T) {
	e := newVPSEnv(t)
	req := SetupRequest{Name: "Tokyo", Host: "203.0.113.5", Password: testPassword, SHA256: testChecksum}

	var prev PlanPreview
	if code := e.post(t, "/api/vps/preflight", req, &prev); code != http.StatusOK {
		t.Fatalf("preflight status %d", code)
	}
	if prev.HostKey != "SHA256:fakehostkey" || prev.Mode != "install" || len(prev.Blocked) != 0 || len(prev.Steps) < 10 || !prev.Report.Root {
		t.Fatalf("preview = %+v", prev)
	}
	// Nothing ran except the read-only pre-flight.
	if len(e.srv.Log) != 1 {
		t.Errorf("preview ran %d commands", len(e.srv.Log))
	}
	if strings.Contains(prev.Text, testPassword) {
		t.Error("the preview contains the password")
	}

	// Running needs the fingerprint confirmed.
	if code := e.post(t, "/api/vps/setup", runRequest{PlanID: prev.PlanID, HostKey: "SHA256:wrong"}, nil); code != http.StatusConflict {
		t.Errorf("unconfirmed host key: status %d", code)
	}
	// ...and a plan runs once: the failed attempt used it up.
	if code := e.post(t, "/api/vps/setup", runRequest{PlanID: prev.PlanID, HostKey: prev.HostKey}, nil); code != http.StatusGone {
		t.Errorf("reused plan: status %d", code)
	}

	e.post(t, "/api/vps/preflight", req, &prev)
	var started struct {
		JobID string `json:"job_id"`
	}
	if code := e.post(t, "/api/vps/setup", runRequest{PlanID: prev.PlanID, HostKey: prev.HostKey}, &started); code != http.StatusOK {
		t.Fatalf("setup status %d", code)
	}
	job := e.waitJob(t, started.JobID)
	if job.Error != "" || job.Outcome == nil {
		t.Fatalf("job = %+v", job)
	}
	o := job.Outcome
	if o.Node != "Tokyo" || o.EgressIP != "203.0.113.5" || !o.DNSOK || o.LatencyMs != 123 || !o.KeyLogin || o.Machine == nil || !o.Machine.HasKey || o.Machine.HostKey != "SHA256:fakehostkey" {
		t.Errorf("outcome = %+v", o)
	}
	if e.reloads == 0 {
		t.Error("the running config wasn't reloaded after importing the node")
	}

	// The node is imported and usable.
	nodes, _ := vps.LoadNodes(e.d.inst.Path("nodes.yaml"))
	if len(nodes) != 1 || nodes[0].Name != "Tokyo" || nodes[0].Proxy["type"] != "vless" || nodes[0].Machine != o.Machine.ID {
		t.Errorf("nodes = %+v", nodes)
	}
	// Key login was proven with a second connection, which didn't use the password.
	last := e.srv.Dials[len(e.srv.Dials)-1]
	if last.Password != "" || len(last.KeyPEM) == 0 || last.HostKey != "SHA256:fakehostkey" {
		t.Errorf("last dial = %+v", last)
	}

	// The password appears nowhere on disk, in the job log, or in the API output.
	_ = filepath.WalkDir(e.home, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if data, _ := os.ReadFile(path); bytes.Contains(data, []byte(testPassword)) {
				t.Errorf("password found in %s", path)
			}
		}
		return nil
	})
	for _, l := range job.Log {
		if strings.Contains(l.Text, testPassword) || strings.Contains(l.Text, nodes[0].Proxy["uuid"].(string)) {
			t.Errorf("job log leaks a secret: %s", l.Text)
		}
	}
	if st, err := os.Stat(filepath.Join(e.home, "vps", "machines.json")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("machines.json: %v %v", st, err)
	}
	logs, _ := filepath.Glob(filepath.Join(e.home, "vps", "logs", "*.log"))
	if len(logs) != 1 {
		t.Errorf("session log files: %v", logs)
	}

	var ms []MachineView
	code, data := e.call(t, http.MethodGet, "/api/vps/machines", fullToken, nil)
	json.Unmarshal(data, &ms)
	if code != 200 || len(ms) != 1 || ms[0].Name != "Tokyo" {
		t.Errorf("machines = %s", data)
	}
}

func TestSetupRefusesWhatItShouldNot(t *testing.T) {
	e := newVPSEnv(t)
	req := SetupRequest{Name: "Tokyo", Host: "203.0.113.5", Password: testPassword}

	// An AI assistant's token reaches none of this.
	for _, p := range []string{"/api/vps/preflight", "/api/vps/setup", "/api/vps/import", "/api/vps/machines/x/run"} {
		if code, _ := e.call(t, http.MethodPost, p, agentToken, req); code != http.StatusForbidden {
			t.Errorf("agent POST %s: status %d", p, code)
		}
	}
	for _, p := range []string{"/api/vps/machines", "/api/vps/machines/x/share", "/api/vps/jobs/x"} {
		if code, _ := e.call(t, http.MethodGet, p, agentToken, nil); code != http.StatusForbidden {
			t.Errorf("agent GET %s: status %d", p, code)
		}
	}

	// Without a verified checksum the plan is blocked and can't be run.
	var prev PlanPreview
	if code := e.post(t, "/api/vps/preflight", req, &prev); code != 200 {
		t.Fatalf("preflight = %d", code)
	}
	if len(prev.Blocked) == 0 || !strings.Contains(prev.Blocked[0], "No verified checksum") {
		t.Errorf("blocked = %v", prev.Blocked)
	}
	if code := e.post(t, "/api/vps/setup", runRequest{PlanID: prev.PlanID, HostKey: prev.HostKey}, nil); code != http.StatusConflict {
		t.Errorf("blocked plan ran: status %d", code)
	}
	if e.srv.Ran("systemctl enable") {
		t.Error("a blocked plan touched the server")
	}

	// A changed host key is refused at connection time.
	e.srv.Key = "SHA256:other"
	req.SHA256 = testChecksum
	e.post(t, "/api/vps/preflight", req, &prev)
	e.srv.Key = "SHA256:fakehostkey"
	var started struct {
		JobID string `json:"job_id"`
	}
	e.post(t, "/api/vps/setup", runRequest{PlanID: prev.PlanID, HostKey: prev.HostKey}, &started)
	job := e.waitJob(t, started.JobID)
	if !strings.Contains(job.Error, "host key changed") {
		t.Errorf("job error = %q", job.Error)
	}

	// Password is required and a bad host is rejected before any connection.
	if code := e.post(t, "/api/vps/preflight", SetupRequest{Host: "203.0.113.5"}, nil); code != http.StatusBadRequest {
		t.Errorf("no password: status %d", code)
	}
	before := len(e.srv.Dials)
	if code := e.post(t, "/api/vps/preflight", SetupRequest{Host: "1.2.3.4; id", Password: "x", SHA256: testChecksum}, nil); code != http.StatusBadRequest {
		t.Errorf("hostile host: status %d", code)
	}
	_ = before
}

func TestMachineActionsAndRotation(t *testing.T) {
	e := newVPSEnv(t)
	creds, _ := vps.NewCreds()
	cfg, _ := vps.ServerConfig(443, "www.microsoft.com", creds)
	e.srv.Handlers = append([]vps.FakeHandler{
		vps.Reply("@@cpu1", metricsSample, 0), // the metrics script mentions systemctl too, so it must match first
		vps.Reply("cat '/etc/sing-box/config.json'", string(cfg), 0),
	}, e.srv.Handlers...)

	m, _ := e.d.vps.store.Add(vps.Machine{Name: "Tokyo", Host: "203.0.113.5", HostKey: "SHA256:fakehostkey", NodeName: "Tokyo", NodePort: 443})
	priv, _, _ := vps.GenerateKey("t")
	e.d.vps.store.SaveKey(m.ID, priv)
	base := "/api/vps/machines/" + m.ID

	var mv MachineView
	if code := e.post(t, base+"/check", nil, &mv); code != 200 || mv.Last == nil || mv.Last.State != vps.StateOnline || mv.Last.Metrics == nil || mv.Last.Metrics.RxBps == 0 {
		t.Fatalf("check = %d %+v", code, mv.Last)
	}
	if code := e.post(t, base+"/quota", vps.Quota{GB: 500, ResetDay: 5}, &mv); code != 200 || mv.Quota.GB != 500 {
		t.Errorf("quota = %d %+v", code, mv.Quota)
	}
	if code := e.post(t, base+"/quota", vps.Quota{GB: -1}, nil); code != http.StatusBadRequest {
		t.Errorf("negative quota: %d", code)
	}

	// Rotate: preview, run, and the new node replaces the old one.
	var prev PlanPreview
	if code := e.post(t, base+"/preview", actionRequest{Kind: "rotate"}, &prev); code != 200 || len(prev.Steps) != 6 {
		t.Fatalf("rotate preview = %d %+v", code, prev)
	}
	if strings.Contains(prev.Text, creds.UUID) {
		t.Error("rotate preview shows the old credentials")
	}
	cmdsBefore := len(e.srv.Log)
	var started struct {
		JobID string `json:"job_id"`
	}
	e.post(t, base+"/run", runRequest{PlanID: prev.PlanID}, &started)
	job := e.waitJob(t, started.JobID)
	if job.Error != "" || job.Outcome == nil || job.Outcome.Node != "Tokyo" {
		t.Fatalf("rotate job = %+v", job)
	}
	if len(e.srv.Log) <= cmdsBefore || e.srv.Files["/etc/sing-box/config.json"] == "" || strings.Contains(e.srv.Files["/etc/sing-box/config.json"], creds.UUID) {
		t.Error("the server's config wasn't replaced with new credentials")
	}
	nodes, _ := vps.LoadNodes(e.d.inst.Path("nodes.yaml"))
	if len(nodes) != 1 || nodes[0].Proxy["uuid"] == creds.UUID {
		t.Errorf("imported node after rotation = %+v", nodes)
	}

	// A preview for one machine can't be run against another, or be run twice.
	e.post(t, base+"/preview", actionRequest{Kind: "restart"}, &prev)
	if code := e.post(t, "/api/vps/machines/"+"mffffff"+"/run", runRequest{PlanID: prev.PlanID}, nil); code != http.StatusNotFound {
		t.Errorf("wrong machine: %d", code)
	}
	if code := e.post(t, base+"/preview", actionRequest{Kind: "format-disk"}, nil); code != http.StatusBadRequest {
		t.Errorf("unknown action: %d", code)
	}

	// Share material comes from the server and includes a decodable QR code.
	code, data := e.call(t, http.MethodGet, base+"/share", fullToken, nil)
	var share ShareView
	json.Unmarshal(data, &share)
	if code != 200 || !strings.HasPrefix(share.Link, "vless://") || share.QRPNG == "" || share.Subscription == "" {
		t.Fatalf("share = %d %s", code, data)
	}

	// Password login: confirmation required.
	if code := e.post(t, base+"/disable-password", map[string]bool{}, nil); code != http.StatusBadRequest {
		t.Errorf("disable-password without confirm: %d", code)
	}
	if code := e.post(t, base+"/disable-password", map[string]bool{"confirm": true}, nil); code != 200 || !e.srv.Ran("sshd -t") {
		t.Errorf("disable-password = %d", code)
	}

	// Removal needs confirmation, and forgets the machine, its key, and its node.
	if code := e.post(t, base+"/remove", map[string]bool{}, nil); code != http.StatusBadRequest {
		t.Errorf("remove without confirm: %d", code)
	}
	if code := e.post(t, base+"/remove", map[string]bool{"confirm": true, "uninstall": true}, nil); code != 200 || !e.srv.Ran("rm -rf /etc/sing-box") {
		t.Errorf("remove = %d", code)
	}
	if ms, _ := e.d.vps.store.List(); len(ms) != 0 {
		t.Errorf("machines left: %+v", ms)
	}
	if nodes, _ := vps.LoadNodes(e.d.inst.Path("nodes.yaml")); len(nodes) != 0 {
		t.Errorf("nodes left: %+v", nodes)
	}
	if _, err := os.Stat(filepath.Join(e.home, "vps", "keys", m.ID)); !os.IsNotExist(err) {
		t.Error("key left behind")
	}
}

const metricsSample = `@@cpu1
cpu  1000 0 500 8000 100 0 0 0 0 0
@@net1
  eth0: 1000000 900 0 0 0 0 0 0 400000 700 0 0 0 0 0 0
@@cpu2
cpu  1100 0 550 8300 150 0 0 0 0 0
@@net2
  eth0: 1300000 950 0 0 0 0 0 0 450000 750 0 0 0 0 0 0
@@iface
eth0
@@mem
MemTotal:        1015808 kB
MemAvailable:     507904 kB
@@disk
20511312 5127828
@@load
0.52 0.40 0.30 1/200 1234
@@uptime
86400.55 170000.00
@@service
active
@@end
`

func TestImportFromTextAndQR(t *testing.T) {
	e := newVPSEnv(t)
	link := vps.VlessRealityLink("friend", "198.51.100.7", 443, "11111111-2222-3333-4444-555555555555", "PUBKEY", "ab12cd34", "www.microsoft.com")
	png, _ := vps.QRPNG(link, 400)

	var prev ImportPreview
	if code := e.post(t, "/api/vps/import", map[string]string{"text": "garbage\n" + link}, &prev); code != 200 || len(prev.Nodes) != 1 || len(prev.Errors) != 1 || prev.Nodes[0].Name != "friend" {
		t.Fatalf("text import = %d %+v", code, prev)
	}
	data, _ := json.Marshal(prev)
	if bytes.Contains(data, []byte("11111111-2222")) {
		t.Error("the import preview shows credentials")
	}
	var applied struct {
		Imported []string `json:"imported"`
	}
	if code := e.post(t, "/api/vps/import/apply", map[string]any{"import_id": prev.ImportID}, &applied); code != 200 || len(applied.Imported) != 1 || applied.Imported[0] != "friend" {
		t.Errorf("apply = %d %+v", code, applied)
	}
	if code := e.post(t, "/api/vps/import/apply", map[string]any{"import_id": prev.ImportID}, nil); code != http.StatusGone {
		t.Errorf("reusing an import: %d", code)
	}

	// The same link from a QR image gets a fresh name instead of clobbering the first.
	img := "data:image/png;base64," + base64Std(png)
	if code := e.post(t, "/api/vps/import", map[string]string{"image": img}, &prev); code != 200 || len(prev.Nodes) != 1 {
		t.Fatalf("qr import = %d %+v", code, prev)
	}
	e.post(t, "/api/vps/import/apply", map[string]any{"import_id": prev.ImportID}, &applied)
	if len(applied.Imported) != 1 || applied.Imported[0] != "friend-2" {
		t.Errorf("second import = %v", applied.Imported)
	}
	if code := e.post(t, "/api/vps/import", map[string]string{"text": " "}, nil); code != http.StatusBadRequest {
		t.Errorf("empty import: %d", code)
	}
	if code := e.post(t, "/api/vps/import", map[string]string{"image": "data:image/png;base64,AAAA"}, nil); code != http.StatusBadRequest {
		t.Errorf("bad image: %d", code)
	}
	// Imported nodes join the health checks.
	ts, _ := e.d.nodeTargets()
	if len(ts) != 2 || !ts[0].TLS {
		t.Errorf("targets = %+v", ts)
	}
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
