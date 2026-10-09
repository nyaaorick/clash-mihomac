package vps

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const metricsFixture = `@@cpu1
cpu  1000 0 500 8000 100 0 0 0 0 0
@@net1
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 5000 10 0 0 0 0 0 0 5000 10 0 0 0 0 0 0
  eth0: 1000000 900 0 0 0 0 0 0 400000 700 0 0 0 0 0 0
@@cpu2
cpu  1100 0 550 8300 150 0 0 0 0 0
@@net2
  eth0: 1300000 950 0 0 0 0 0 0 450000 750 0 0 0 0 0 0
    lo: 5100 10 0 0 0 0 0 0 5100 10 0 0 0 0 0 0
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
@@version
sing-box version 1.12.0
@@ports
0.0.0.0:22
*:443
[::]:22
@@certs
/etc/ssl/a.crt notAfter=Oct 20 12:00:00 2026 GMT
@@end
`

func TestParseMetrics(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	m, err := ParseMetrics(metricsFixture, now)
	if err != nil {
		t.Fatal(err)
	}
	// Between the samples 500 jiffies passed and 350 of them were idle (idle + iowait): 30% busy.
	if m.CPUPercent < 29.9 || m.CPUPercent > 30.1 {
		t.Errorf("cpu = %.1f", m.CPUPercent)
	}
	if m.RxBps != 300000 || m.TxBps != 50000 || m.RxTotal != 1300000 || m.TxTotal != 450000 || m.Iface != "eth0" {
		t.Errorf("net = %+v", m)
	}
	if m.MemTotalMB != 992 || m.MemUsedPct != 50 || m.DiskUsedPct < 24.9 || m.DiskUsedPct > 25.1 || m.DiskTotalGB < 19.5 || m.DiskTotalGB > 19.6 {
		t.Errorf("mem/disk = %+v", m)
	}
	if m.Load1 != 0.52 || m.UptimeSecs != 86400 || !m.ServiceActive || m.ServiceVersion != "1.12.0" {
		t.Errorf("load/service = %+v", m)
	}
	if len(m.Listening) != 2 || m.Listening[0] != 22 || m.Listening[1] != 443 {
		t.Errorf("ports = %v", m.Listening)
	}
	if len(m.CertExpiry) != 1 || m.CertExpiry[0].Expires.Month() != time.October || m.CertExpiry[0].Expires.Day() != 20 {
		t.Errorf("certs = %+v", m.CertExpiry)
	}
	state, why := Judge(m, now)
	if state != StateDegraded || len(why) != 1 || !strings.Contains(why[0], "expires in 11 days") {
		t.Errorf("judge = %s %v", state, why)
	}
	m.CertExpiry = nil
	if state, _ := Judge(m, now); state != StateOnline {
		t.Errorf("healthy machine judged %s", state)
	}
	m.ServiceActive, m.DiskUsedPct = false, 95
	if state, why := Judge(m, now); state != StateDegraded || len(why) != 2 {
		t.Errorf("sick machine: %s %v", state, why)
	}
	if _, err := ParseMetrics("garbage", now); err == nil {
		t.Error("garbage accepted")
	}
}

func TestMetricsScriptIsReadOnlyAndCollects(t *testing.T) {
	for _, bad := range []string{"rm ", "> /", "systemctl restart", "apt", "chmod", "kill"} {
		if strings.Contains(metricsScript, bad) {
			t.Errorf("metrics script contains %q", bad)
		}
	}
	srv := &FakeServer{Handlers: []FakeHandler{Reply("@@cpu1", metricsFixture, 0)}}
	conn, _ := srv.Dial(context.Background(), Target{})
	m, err := Collect(context.Background(), conn, time.Now())
	if err != nil || !m.ServiceActive || len(srv.Log) != 1 {
		t.Errorf("Collect = %+v, %v (%d commands)", m, err, len(srv.Log))
	}
}

func TestTrafficAccounting(t *testing.T) {
	q := Quota{GB: 1000, ResetDay: 15}
	reading := func(rx, tx uint64) Metrics { return Metrics{RxTotal: rx, TxTotal: tx} }
	at := func(d int) time.Time { return time.Date(2026, 10, d, 12, 0, 0, 0, time.UTC) }

	var a TrafficAcc
	a = a.Account(reading(100, 50), q, at(16)) // first reading starts the period
	if a.Period != "2026-10" || a.Bytes != 0 {
		t.Fatalf("start = %+v", a)
	}
	a = a.Account(reading(1100, 550), q, at(17))
	if a.Bytes != 1500 {
		t.Errorf("after traffic = %d", a.Bytes)
	}
	a = a.Account(reading(200, 100), q, at(18)) // the server rebooted: counters restarted
	if a.Bytes != 1800 {
		t.Errorf("after reboot = %d, want 1800 (the new counters count in full)", a.Bytes)
	}
	a = a.Account(reading(300, 100), q, time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)) // still the Oct 15 period
	if a.Period != "2026-10" || a.Bytes != 1900 {
		t.Errorf("before reset = %+v", a)
	}
	a = a.Account(reading(400, 100), q, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
	if a.Period != "2026-11" || a.Bytes != 0 {
		t.Errorf("after reset = %+v", a)
	}

	for _, c := range []struct {
		day, reset int
		month      time.Month
		want       string
	}{{3, 0, time.January, "2026-01"}, {3, 15, time.January, "2025-12"}, {15, 15, time.January, "2026-01"}, {20, 40, time.March, "2026-03"}} {
		if got := BillingPeriod(time.Date(2026, c.month, c.day, 0, 0, 0, 0, time.UTC), c.reset); got != c.want {
			t.Errorf("period(%d/%d reset %d) = %s, want %s", c.month, c.day, c.reset, got, c.want)
		}
	}
}

func TestStore(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "vps")}
	m, err := s.Add(Machine{Name: "Tokyo", Host: "203.0.113.5"})
	if err != nil || !idRE.MatchString(m.ID) || m.Port != 22 || m.User != "root" || m.Added.IsZero() {
		t.Fatalf("Add = %+v, %v", m, err)
	}
	if _, err := s.Add(Machine{Name: "tokyo", Host: "198.51.100.1"}); err == nil {
		t.Error("duplicate name accepted")
	}
	if _, err := s.Add(Machine{Name: "Other", Host: "203.0.113.5", Port: 22}); err == nil {
		t.Error("duplicate address accepted")
	}
	for _, bad := range []Machine{{Name: "x'y", Host: "h"}, {Name: "ok", Host: "a b"}, {Name: "", Host: "h"}} {
		if _, err := s.Add(bad); err == nil {
			t.Errorf("Add(%+v) accepted", bad)
		}
	}
	got, err := s.Get("TOKYO")
	if err != nil || got.ID != m.ID {
		t.Errorf("Get by name = %+v, %v", got, err)
	}
	if info, err := os.Stat(filepath.Join(s.Dir, "machines.json")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("machines.json: %v %v", info, err)
	}

	priv, _, _ := GenerateKey("test")
	if err := s.SaveKey(m.ID, priv); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(filepath.Join(s.Dir, "keys", m.ID)); info.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v", info.Mode())
	}
	m, _ = s.Get(m.ID)
	tg, err := s.Target(m)
	if err != nil || len(tg.KeyPEM) == 0 || tg.Password != "" {
		t.Errorf("Target = %+v, %v", tg, err)
	}
	if err := s.SaveKey("../../etc/passwd", priv); err == nil {
		t.Error("path traversal in key id accepted")
	}

	up, err := s.Update(m.ID, func(x *Machine) { x.Quota = Quota{GB: 500}; x.ID = "tampered" })
	if err != nil || up.Quota.GB != 500 || up.ID != m.ID {
		t.Errorf("Update = %+v, %v", up, err)
	}
	if err := s.Remove(m.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "keys", m.ID)); !os.IsNotExist(err) {
		t.Error("key not deleted with the machine")
	}
	if ms, _ := s.List(); len(ms) != 0 {
		t.Errorf("machines left: %+v", ms)
	}
	if err := s.Remove(m.ID); err == nil {
		t.Error("removing twice should fail")
	}
}

func TestActionPlans(t *testing.T) {
	m := Machine{ID: "m000001", Name: "Tokyo", Host: "203.0.113.5", NodeName: "tokyo", NodePort: 8443}
	p, err := ActionPlan(ActionRestart, m, 0, "")
	if err != nil || stepIDs(p) != "restart,active,listening" || !strings.Contains(p.Steps[2].Cmd, ":8443 ") {
		t.Errorf("restart = %v %v", stepIDs(p), err)
	}
	p, err = ActionPlan(ActionRotate, m, 8443, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if stepIDs(p) != "backup,config,check-config,restart,active,listening" || p.Link == "" || p.Creds.UUID == "" {
		t.Errorf("rotate = %v", stepIDs(p))
	}
	if !strings.Contains(string(p.Steps[1].Stdin), p.Creds.UUID) || strings.Contains(p.Render(), p.Creds.UUID) {
		t.Error("rotation config must carry the new credentials, and the preview must hide them")
	}
	if p.Steps[0].Undo == "" || !strings.Contains(p.Steps[0].Undo, "config.json.prev") {
		t.Errorf("rotation can't be undone: %+v", p.Steps[0])
	}
	// A failed rotation restores the old config.
	srv := scriptedServer()
	srv.Handlers = append([]FakeHandler{Reply("systemctl is-active sing-box", "failed\n", 3)}, srv.Handlers...)
	conn, _ := srv.Dial(context.Background(), Target{})
	if err := Execute(context.Background(), conn, p, mustLog(t, p.Redactor()), nil); err == nil || !srv.Ran("mv -f /etc/sing-box/config.json.prev /etc/sing-box/config.json") {
		t.Errorf("rotation failure not rolled back: %v / %v", err, srv.Log)
	}

	p, err = ActionPlan(ActionReboot, m, 0, "")
	if err != nil || len(p.Steps) != 1 || !strings.Contains(p.Steps[0].Cmd, "systemctl reboot") {
		t.Errorf("reboot = %+v %v", p, err)
	}
	if _, err := ActionPlan("format-disk", m, 0, ""); err == nil {
		t.Error("unknown action accepted")
	}
	bad := m
	bad.Host = "1.2.3.4; rm -rf /"
	if _, err := ActionPlan(ActionRestart, bad, 0, ""); err == nil {
		t.Error("hostile saved host accepted")
	}
}
