package vps

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const goodSum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func debianReport(t *testing.T) Report {
	t.Helper()
	r := ParsePreflight(readFixture(t, "preflight_debian.txt"))
	r.Issues = Assess(r, 443)
	return r
}

func installOpts(t *testing.T) Options {
	return Options{Mode: ModeInstall, Name: "tokyo", Host: "203.0.113.5", Port: 443, SHA256: goodSum, Report: debianReport(t)}
}

func stepIDs(p Plan) string {
	var ids []string
	for _, s := range p.Steps {
		ids = append(ids, s.ID)
	}
	return strings.Join(ids, ",")
}

func TestInstallPlanSteps(t *testing.T) {
	p, err := BuildPlan(installOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Blocked) != 0 {
		t.Fatalf("blocked: %v", p.Blocked)
	}
	want := "prereqs,download,verify,install-binary,user,config,check-config,unit,bbr,firewall,start,active,listening,cleanup"
	if got := stepIDs(p); got != want {
		t.Errorf("steps = %s\nwant    %s", got, want)
	}
	for _, s := range p.Steps {
		if s.Title == "" || s.Why == "" || s.Cmd == "" {
			t.Errorf("step %s is missing its title, explanation, or command", s.ID)
		}
	}
	by := map[string]Step{}
	for _, s := range p.Steps {
		by[s.ID] = s
	}
	if !strings.Contains(by["verify"].Cmd, goodSum) || !strings.Contains(by["download"].Cmd, "sing-box-1.12.0-linux-amd64.tar.gz") || !strings.Contains(by["firewall"].Cmd, "ufw allow 443/tcp") {
		t.Errorf("download/verify/firewall steps wrong: %+v", by)
	}
	if p.Link == "" || !strings.HasPrefix(p.Link, "vless://"+p.Creds.UUID+"@203.0.113.5:443?") {
		t.Errorf("link = %q", p.Link)
	}
}

func TestPlanNeedsAVerifiedChecksum(t *testing.T) {
	o := installOpts(t)
	o.SHA256 = ""
	p, err := BuildPlan(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Blocked) == 0 || !strings.Contains(p.Blocked[0], "No verified checksum") {
		t.Errorf("blocked = %v", p.Blocked)
	}
	if err := Execute(context.Background(), nil, p, mustLog(t, nil), nil); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Errorf("Execute ran a blocked plan: %v", err)
	}
	o.Release = Release{Version: "1.12.0", SHA256: map[string]string{"amd64": goodSum}}
	if p, _ := BuildPlan(o); len(p.Blocked) != 0 {
		t.Errorf("a pinned checksum should unblock: %v", p.Blocked)
	}
}

func TestPlanBlockedByPreflightErrors(t *testing.T) {
	o := installOpts(t)
	o.Report.Root = false
	o.Report.Issues = Assess(o.Report, 443)
	p, _ := BuildPlan(o)
	if len(p.Blocked) != 1 || !strings.Contains(p.Blocked[0], "not logged in as root") {
		t.Errorf("blocked = %v", p.Blocked)
	}
}

func TestOptionsAreValidatedBeforeTheyReachACommand(t *testing.T) {
	bad := map[string]func(*Options){
		"host injection": func(o *Options) { o.Host = "1.2.3.4; rm -rf /" },
		"host quote":     func(o *Options) { o.Host = "a'b" },
		"sni injection":  func(o *Options) { o.SNI = "a.com\"; id" },
		"name quote":     func(o *Options) { o.Name = "x'; id #" },
		"port zero":      func(o *Options) { o.Port = -1 },
		"version":        func(o *Options) { o.Release = Release{Version: "1.0.0; id"} },
		"sha":            func(o *Options) { o.SHA256 = "nothex" },
		"mode":           func(o *Options) { o.Mode = "destroy" },
	}
	for name, mut := range bad {
		o := installOpts(t)
		mut(&o)
		if _, err := BuildPlan(o); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCredsAndConfigRoundTrip(t *testing.T) {
	c, err := NewCreds()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.UUID) != 36 || c.UUID[14] != '4' || len(c.ShortID) != 16 || len(c.PrivateKey) != 43 || len(c.PublicKey) != 43 || c.PrivateKey == c.PublicKey {
		t.Errorf("creds = %+v", c)
	}
	if pub, err := PublicFromPrivate(c.PrivateKey); err != nil || pub != c.PublicKey {
		t.Errorf("derived public key %q (%v), want %q", pub, err, c.PublicKey)
	}
	cfg, err := ServerConfig(8443, "www.example.com", c)
	if err != nil {
		t.Fatal(err)
	}
	port, sni, back, err := ParseServerConfig(cfg)
	if err != nil || port != 8443 || sni != "www.example.com" || back != c {
		t.Errorf("round trip = %d %s %+v %v", port, sni, back, err)
	}
	if _, _, _, err := ParseServerConfig([]byte(`{"inbounds":[{"type":"mixed"}]}`)); err == nil {
		t.Error("foreign config accepted")
	}
	c2, _ := NewCreds()
	if c2.UUID == c.UUID || c2.PrivateKey == c.PrivateKey {
		t.Error("credentials repeat")
	}
}

func TestRenderHidesSecretsButShowsEverythingElse(t *testing.T) {
	p, _ := BuildPlan(installOpts(t))
	text := p.Render()
	for _, secret := range []string{p.Creds.UUID, p.Creds.PrivateKey, p.Creds.ShortID, p.Link} {
		if strings.Contains(text, secret) {
			t.Errorf("plan preview leaks %q", secret)
		}
	}
	for _, want := range []string{"1. Install download tools", "$ DEBIAN_FRONTEND=noninteractive apt-get", "writes /etc/sing-box/config.json", `"private_key": "••••"`, "sha256sum -c", "ufw allow 443/tcp"} {
		if !strings.Contains(text, want) {
			t.Errorf("preview missing %q", want)
		}
	}
}

func mustLog(t *testing.T, red *Redactor) *SessionLog {
	t.Helper()
	if red == nil {
		red = NewRedactor()
	}
	l, err := NewSessionLog(red, "")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func scriptedServer() *FakeServer {
	return &FakeServer{Handlers: []FakeHandler{
		Reply("systemctl is-active sing-box", "active\n", 0),
		Reply("ss -ltn", "listening\n", 0),
		Reply("version | head -1", "sing-box version 1.12.0\n", 0),
		Reply("api.ipify.org", "203.0.113.5\n", 0),
		Reply("getent hosts", "93.184.216.34 example.com\n", 0),
	}}
}

func TestExecuteInstallEndToEnd(t *testing.T) {
	p, _ := BuildPlan(installOpts(t))
	srv := scriptedServer()
	conn, _ := srv.Dial(context.Background(), Target{})
	log := mustLog(t, p.Redactor("hunter2-password"))
	var seen []string
	if err := Execute(context.Background(), conn, p, log, func(done, total int, title string) { seen = append(seen, title) }); err != nil {
		t.Fatal(err)
	}
	if len(srv.Log) != len(p.Steps) || seen[len(seen)-1] != "done" {
		t.Errorf("ran %d commands for %d steps; progress = %v", len(srv.Log), len(p.Steps), seen)
	}
	// The config reached the server intact, with permissions set in the same command.
	cfg := srv.Files[confPath]
	if !strings.Contains(cfg, p.Creds.UUID) || !strings.Contains(cfg, p.Creds.PrivateKey) {
		t.Errorf("uploaded config = %s", cfg)
	}
	if !strings.Contains(srv.Files[unitPath], "ExecStart=/usr/local/bin/sing-box run") || !strings.Contains(srv.Files[bbrPath], "bbr") {
		t.Error("unit or sysctl file not written")
	}
	// The log never holds credentials.
	var all strings.Builder
	for _, l := range log.Lines() {
		all.WriteString(l.Text + "\n")
	}
	for _, secret := range []string{p.Creds.UUID, p.Creds.PrivateKey, p.Creds.ShortID, "hunter2-password"} {
		if strings.Contains(all.String(), secret) {
			t.Errorf("session log leaks %q", secret)
		}
	}
	if !strings.Contains(all.String(), "setup finished") {
		t.Error("log has no ending")
	}

	out := Finish(context.Background(), conn, p, log)
	if out.Version != "1.12.0" || out.EgressIP != "203.0.113.5" || !out.DNSOK || out.Link != p.Link {
		t.Errorf("outcome = %+v", out)
	}
}

func TestExecuteStopsAtFirstFailure(t *testing.T) {
	p, _ := BuildPlan(installOpts(t))
	srv := scriptedServer()
	srv.Handlers = append([]FakeHandler{{Match: "sha256sum -c", Reply: func(string, []byte) Result {
		return Result{Stderr: "sb.tar.gz: FAILED\nsha256sum: WARNING: 1 computed checksum did NOT match\n", Exit: 1}
	}}}, srv.Handlers...)
	conn, _ := srv.Dial(context.Background(), Target{})
	log := mustLog(t, p.Redactor())
	err := Execute(context.Background(), conn, p, log, nil)
	var se *StepError
	if !errors.As(err, &se) || se.Step.ID != "verify" || se.Result.Exit != 1 {
		t.Fatalf("err = %v", err)
	}
	if srv.Ran("install -m 0755") || srv.Ran("systemctl enable") {
		t.Error("steps after the failed checksum ran")
	}
	if !strings.Contains(joinLog(log), "did NOT match") {
		t.Errorf("failure output missing from the log:\n%s", joinLog(log))
	}
}

func joinLog(l *SessionLog) string {
	var b strings.Builder
	for _, x := range l.Lines() {
		b.WriteString(x.Text + "\n")
	}
	return b.String()
}

func TestUpgradeRollsBackWhenTheNewBinaryDoesNotStart(t *testing.T) {
	r := debianReport(t)
	r.Ours = Install{Binary: true, Config: true, Unit: true, Active: true, Version: "1.11.0"}
	r.OursFound = true
	r.PortsInUse = map[int]string{443: "sing-box"}
	r.Issues = Assess(r, 443)
	if ChooseMode(r) != ModeUpgrade {
		t.Fatalf("mode = %s", ChooseMode(r))
	}
	p, err := BuildPlan(Options{Mode: ModeUpgrade, Name: "tokyo", Host: "203.0.113.5", SHA256: goodSum, Report: r, Creds: Creds{UUID: "u-u-i-d", PublicKey: "pk"}})
	if err != nil || len(p.Blocked) != 0 {
		t.Fatalf("plan = %+v, %v", p.Blocked, err)
	}
	if got := stepIDs(p); got != "prereqs,download,verify,install-binary,restart,active,listening,cleanup" {
		t.Errorf("upgrade steps = %s", got)
	}
	if p.Creds.UUID != "u-u-i-d" || srvHas(p, "config") {
		t.Error("an upgrade must keep the config and credentials")
	}
	srv := scriptedServer()
	srv.Handlers = append([]FakeHandler{Reply("systemctl is-active sing-box", "failed\n", 3)}, srv.Handlers...)
	conn, _ := srv.Dial(context.Background(), Target{})
	err = Execute(context.Background(), conn, p, mustLog(t, p.Redactor()), nil)
	var se *StepError
	if !errors.As(err, &se) || se.Step.ID != "active" {
		t.Fatalf("err = %v", err)
	}
	if !srv.Ran("mv -f /usr/local/bin/sing-box.prev /usr/local/bin/sing-box") {
		t.Errorf("previous binary not restored; commands: %v", srv.Log)
	}
}

func srvHas(p Plan, id string) bool {
	for _, s := range p.Steps {
		if s.ID == id {
			return true
		}
	}
	return false
}

func TestRepairAndReinstallPlans(t *testing.T) {
	r := debianReport(t)
	r.Ours = Install{Binary: true, Config: true}
	r.OursFound = true
	r.Issues = Assess(r, 443)
	if ChooseMode(r) != ModeRepair {
		t.Fatalf("mode = %s", ChooseMode(r))
	}
	creds, _ := NewCreds()
	p, err := BuildPlan(Options{Mode: ModeRepair, Name: "tokyo", Host: "203.0.113.5", Report: r, Creds: creds})
	if err != nil || len(p.Blocked) != 0 {
		t.Fatalf("repair plan: %v %v", p.Blocked, err)
	}
	// Binary and config exist, the unit doesn't: no download, no config rewrite, but the unit is restored.
	if got := stepIDs(p); got != "user,check-config,unit,bbr,firewall,start,active,listening" {
		t.Errorf("repair steps = %s", got)
	}

	r.Ours = Install{Unit: true}
	p, _ = BuildPlan(Options{Mode: ModeRepair, Name: "tokyo", Host: "203.0.113.5", SHA256: goodSum, Report: r})
	if len(p.Blocked) == 0 || !strings.Contains(strings.Join(p.Blocked, " "), "credentials can't be recovered") {
		t.Errorf("repair without a config or credentials must not invent new ones: %v", p.Blocked)
	}

	r.Ours = Install{Binary: true, Config: true, Unit: true, Active: true}
	r.PortsInUse = map[int]string{443: "sing-box"}
	r.Issues = Assess(r, 443)
	p, _ = BuildPlan(Options{Mode: ModeReinstall, Name: "tokyo", Host: "203.0.113.5", SHA256: goodSum, Report: r})
	ids := stepIDs(p)
	if !strings.HasPrefix(ids, "remove-old,prereqs,") || !strings.Contains(ids, ",config,") || p.Creds.UUID == "" {
		t.Errorf("reinstall steps = %s", ids)
	}
	if rm := p.Steps[0].Cmd; strings.Contains(rm, "/etc/ssh") || !strings.Contains(rm, "/etc/sing-box") {
		t.Errorf("remove step = %s", rm)
	}
}

func TestReadExistingRecoversTheShareLink(t *testing.T) {
	c, _ := NewCreds()
	cfg, _ := ServerConfig(443, "www.microsoft.com", c)
	srv := &FakeServer{Handlers: []FakeHandler{Reply("cat '/etc/sing-box/config.json'", string(cfg), 0)}}
	conn, _ := srv.Dial(context.Background(), Target{})
	port, sni, got, link, err := ReadExisting(context.Background(), conn, "203.0.113.5", "tokyo")
	if err != nil || port != 443 || sni != "www.microsoft.com" || got != c {
		t.Fatalf("ReadExisting = %d %s %+v %v", port, sni, got, err)
	}
	n, err := ParseLink(link)
	if err != nil || n.Proxy["uuid"] != c.UUID || n.Proxy["reality-opts"].(map[string]any)["public-key"] != c.PublicKey {
		t.Errorf("link %q parses to %+v, %v", link, n, err)
	}
	srv2 := &FakeServer{Handlers: []FakeHandler{Reply("cat '/etc/sing-box/config.json'", "", 1)}}
	conn2, _ := srv2.Dial(context.Background(), Target{})
	if _, _, _, _, err := ReadExisting(context.Background(), conn2, "h", "n"); err == nil {
		t.Error("missing config accepted")
	}
}

func TestKeyInstallation(t *testing.T) {
	srv := &FakeServer{}
	conn, _ := srv.Dial(context.Background(), Target{})
	_, pub, _ := GenerateKey("mihomac")
	if err := InstallKey(context.Background(), conn, pub); err != nil {
		t.Fatal(err)
	}
	if !srv.Ran("authorized_keys") || !strings.Contains(srv.Log[0], "grep -qxF") {
		t.Errorf("commands = %v", srv.Log)
	}
	if err := InstallKey(context.Background(), conn, "ssh-ed25519 AAAA'; rm -rf / #"); err == nil {
		t.Error("key with a quote accepted")
	}
	if err := DisablePasswordLogin(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	if !srv.Ran("sshd -t") || !strings.Contains(srv.Files["/etc/ssh/sshd_config.d/00-mihomac.conf"], "PasswordAuthentication no") {
		t.Errorf("password login change: %v / %v", srv.Log, srv.Files)
	}
	failing := &FakeServer{Handlers: []FakeHandler{{Match: "sshd -t", Reply: func(string, []byte) Result { return Result{Stderr: "bad config", Exit: 1} }}}}
	c2, _ := failing.Dial(context.Background(), Target{})
	if err := DisablePasswordLogin(context.Background(), c2); err == nil {
		t.Error("failure not reported")
	}
}
