package vps

import (
	"context"
	"os"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParsePreflightDebian(t *testing.T) {
	r := ParsePreflight(readFixture(t, "preflight_debian.txt"))
	if !r.Root || !r.Systemd || r.Arch != "amd64" || r.OSID != "debian" || r.OS != "Debian GNU/Linux 12 (bookworm)" || r.PkgMgr != "apt-get" || r.Firewall != "ufw" {
		t.Errorf("report = %+v", r)
	}
	if r.PortsInUse[22] != "sshd" || r.PortsInUse[80] != "nginx" || r.PortsInUse[53] != "systemd-resolve" || len(r.PortsInUse) != 3 {
		t.Errorf("ports = %v", r.PortsInUse)
	}
	if r.NTPSynced == nil || !*r.NTPSynced || r.MemMB != 981 || r.DiskFreeMB != 10240 || !r.BBRAvail || r.BBRActive {
		t.Errorf("report = %+v", r)
	}
	if len(r.Existing) != 1 || r.Existing[0] != "x-ui.service" {
		t.Errorf("existing = %v", r.Existing)
	}
	issues := Assess(r, 443)
	if (Report{Issues: issues}).Blocked() {
		t.Errorf("a healthy server was blocked: %+v", issues)
	}
	if !hasIssue(issues, SevWarn, "x-ui.service") {
		t.Errorf("existing proxy software not reported: %+v", issues)
	}
	if blocked := Assess(r, 80); !hasIssue(blocked, SevError, "Port 80 is already in use by nginx") {
		t.Errorf("port clash not reported: %+v", blocked)
	}
}

func hasIssue(is []Issue, sev, substr string) bool {
	for _, i := range is {
		if i.Severity == sev && strings.Contains(i.Message, substr) {
			return true
		}
	}
	return false
}

func TestAssessProblemServer(t *testing.T) {
	r := ParsePreflight(readFixture(t, "preflight_problem.txt"))
	if r.Ours != (Install{Binary: true, Config: true, Active: true, Version: "1.11.4"}) || !r.OursFound {
		t.Errorf("previous install = %+v", r.Ours)
	}
	if r.Arch != "armv7l" || r.OursFound != true || r.Root || r.Systemd {
		t.Errorf("report = %+v", r)
	}
	issues := Assess(r, 443)
	for _, want := range []struct{ sev, msg string }{
		{SevError, "not logged in as root"}, {SevError, "systemd"}, {SevError, "Unsupported CPU architecture"}, {SevError, "package manager"},
		{SevError, "Port 443 is already in use by nginx"}, {SevError, "100 MB of free disk"},
		{SevWarn, "alpine"[:0] + "isn't one of the systems"}, {SevWarn, "NTP"}, {SevWarn, "128 MB"}, {SevWarn, "/etc/v2ray-agent"},
		{SevInfo, "BBR"}, {SevInfo, "No managed firewall"},
	} {
		if !hasIssue(issues, want.sev, want.msg) {
			t.Errorf("missing %s issue containing %q in %+v", want.sev, want.msg, issues)
		}
	}
}

func TestOurOwnProxyOnThePortIsNotAClash(t *testing.T) {
	r := Report{Root: true, Systemd: true, Arch: "amd64", PkgMgr: "apt-get", OSID: "debian", OursFound: true, PortsInUse: map[int]string{443: "sing-box"}, BBRAvail: true}
	if hasIssue(Assess(r, 443), SevError, "Port 443") {
		t.Error("our own sing-box flagged as a port clash")
	}
}

func TestPreflightRunsOneReadOnlyScript(t *testing.T) {
	srv := &FakeServer{Handlers: []FakeHandler{Reply("@@uid", readFixture(t, "preflight_debian.txt"), 0)}}
	conn, _ := srv.Dial(context.Background(), Target{})
	r, err := Preflight(context.Background(), conn, 443)
	if err != nil || !r.Reachable || r.HostKey != "SHA256:fakehostkey" || r.Blocked() {
		t.Fatalf("report = %+v, %v", r, err)
	}
	if len(srv.Log) != 1 {
		t.Errorf("preflight ran %d commands, want 1", len(srv.Log))
	}
	for _, bad := range []string{" rm ", "apt-get install", "systemctl restart", "> /", "chmod", "sed -i"} {
		if strings.Contains(preflightScript, bad) {
			t.Errorf("preflight script contains %q; it must be read-only", bad)
		}
	}
}

func TestShellQuoting(t *testing.T) {
	if got := shq(`it's $(bad) "x"`); got != `'it'\''s $(bad) "x"'` {
		t.Errorf("shq = %s", got)
	}
}
