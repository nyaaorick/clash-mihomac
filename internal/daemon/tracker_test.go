package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/rules"
)

func cc(id, host, process, rule, payload string, chains ...string) ctrlConn {
	var c ctrlConn
	c.ID = id
	c.Start = time.Now()
	c.Metadata.Host = host
	c.Metadata.DestinationPort = "443"
	c.Metadata.DestinationIP = "93.184.216.34"
	c.Metadata.Process = process
	c.Metadata.Type = "Tun"
	c.Rule, c.RulePayload, c.Chains = rule, payload, chains
	return c
}

func TestTrackerKeepsClosedConnections(t *testing.T) {
	tr := NewTracker()
	tr.Update([]ctrlConn{cc("a", "example.com", "curl", "Match", "", "DIRECT"), cc("b", "bilibili.com", "Safari", "DomainSuffix", "bilibili.com", "DIRECT")})
	tr.Update([]ctrlConn{cc("b", "bilibili.com", "Safari", "DomainSuffix", "bilibili.com", "DIRECT")})

	a, ok := tr.Get("a")
	if !ok || a.End == nil {
		t.Fatalf("closed connection lost or not marked closed: %+v, %v", a, ok)
	}
	if b, _ := tr.Get("b"); b.End != nil {
		t.Error("live connection marked closed")
	}
	if got := tr.List("safari", 10); len(got) != 1 || got[0].ID != "b" {
		t.Errorf("filter by process = %+v", got)
	}
	if got := tr.List("", 1); len(got) != 1 {
		t.Errorf("limit ignored: %d results", len(got))
	}
}

func TestTrackerBoundsHistory(t *testing.T) {
	tr := NewTracker()
	tr.maxClosed = 3
	for i := 0; i < 10; i++ {
		tr.Update([]ctrlConn{cc(string(rune('a'+i)), "x.com", "", "Match", "", "DIRECT")})
	}
	tr.Reset()
	if n := len(tr.closed); n != 3 {
		t.Errorf("closed history = %d, want 3", n)
	}
}

func TestLogsForConnection(t *testing.T) {
	tr := NewTracker()
	tr.Update([]ctrlConn{cc("a", "example.com", "curl", "Match", "", "DIRECT")})
	tr.AddLog("warning", "dial tcp example.com:443: i/o timeout")
	tr.AddLog("warning", "dial tcp other.com:443: refused")
	c, _ := tr.Get("a")
	logs := tr.LogsFor(c)
	if len(logs) != 1 || !strings.Contains(logs[0].Message, "example.com") {
		t.Errorf("logs = %+v", logs)
	}
}

func TestFailedDialBecomesConnection(t *testing.T) {
	tr := NewTracker()
	tr.AddLog("warning", "[TCP] dial iface:en0 (match DomainSuffix/example.com) 127.0.0.1:61261(curl) --> example.com:443 error: dial tcp 198.18.0.178:443: i/o timeout")
	tr.AddLog("warning", "[TCP] dial Proxy (match Match/) 127.0.0.1:5000 --> 1.2.3.4:80 error: connect failed")
	tr.AddLog("warning", "some unrelated warning")

	got := tr.List("", 10)
	if len(got) != 2 {
		t.Fatalf("connections = %+v", got)
	}
	var c Conn
	for _, x := range got {
		if x.Host == "example.com" {
			c = x
		}
	}
	if c.Process != "curl" || c.Rule != "DomainSuffix" || c.RulePayload != "example.com" || c.DestIP != "198.18.0.178" ||
		c.DestPort != "443" || c.Chains[0] != "iface:en0" || c.End == nil || !strings.Contains(c.Error, "i/o timeout") {
		t.Errorf("parsed = %+v", c)
	}

	e := Explain(c, []ctrlRule{{Type: "DomainSuffix", Payload: "example.com", Proxy: "iface:en0"}}, []rules.Source{{Kind: "user", Name: "#1"}}, "en0")
	if !strings.Contains(e.Summary, "The connection failed") || !strings.Contains(e.Summary, "fake-ip") {
		t.Errorf("summary = %s", e.Summary)
	}
}

func TestExplainUserRuleThroughGroup(t *testing.T) {
	ctrl := []ctrlRule{
		{Type: "DomainSuffix", Payload: "corp.example.com", Proxy: "iface:en1"},
		{Type: "DomainSuffix", Payload: "openai.com", Proxy: "Proxy"},
		{Type: "Match", Proxy: "DIRECT"},
	}
	sources := []rules.Source{
		{Kind: "user", Name: "#1", Note: "intranet"},
		{Kind: "user", Name: "#2", Note: "AI tools"},
		{Kind: "config", Index: 1},
	}
	c := Conn{Host: "api.openai.com", DestIP: "1.2.3.4", DestPort: "443", Process: "Cursor", Rule: "DomainSuffix", RulePayload: "openai.com", Chains: []string{"HK-1", "Proxy"}}
	e := Explain(c, ctrl, sources, "en0")

	for _, want := range []string{"Cursor connected to api.openai.com:443 (1.2.3.4)", "rule #2 `DomainSuffix,openai.com,Proxy`", "your rule #2 (AI tools)", "The Proxy group picked node HK-1"} {
		if !strings.Contains(e.Summary, want) {
			t.Errorf("summary missing %q:\n%s", want, e.Summary)
		}
	}
	if len(e.Path) != 4 || e.Path[2].Label != "HK-1" {
		t.Errorf("path = %+v", e.Path)
	}
}

func TestExplainInterfaceAndFallback(t *testing.T) {
	ctrl := []ctrlRule{{Type: "IPCIDR", Payload: "10.20.0.0/16", Proxy: "iface:en1"}, {Type: "Match", Proxy: "DIRECT"}}
	sources := []rules.Source{{Kind: "user", Name: "#1"}, {Kind: "config", Index: 1}}

	e := Explain(Conn{DestIP: "10.20.1.5", DestPort: "22", Rule: "IPCIDR", RulePayload: "10.20.0.0/16", Chains: []string{"iface:en1"}}, ctrl, sources, "en0")
	if e.Out.Interface != "en1" || !strings.Contains(e.Summary, "directly through en1") {
		t.Errorf("iface: %+v / %s", e.Out, e.Summary)
	}
	if !strings.Contains(e.Summary, "An unidentified process") {
		t.Errorf("summary = %s", e.Summary)
	}

	e = Explain(Conn{Host: "example.com", DestPort: "443", Process: "curl", Rule: "Match", Chains: []string{"DIRECT"}}, ctrl, sources, "en0")
	if !strings.Contains(e.Summary, "final MATCH rule sent it to DIRECT") || !strings.Contains(e.Summary, "default route (en0)") {
		t.Errorf("fallback: %s", e.Summary)
	}

	e = Explain(Conn{Host: "ads.example", DestPort: "443", Process: "Safari", Rule: "Match", Chains: []string{"REJECT"}}, ctrl, sources, "en0")
	if !e.Out.Blocked || !strings.Contains(e.Summary, "blocked") {
		t.Errorf("reject: %s", e.Summary)
	}
}
