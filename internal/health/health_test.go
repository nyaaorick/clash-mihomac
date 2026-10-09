package health

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeDelay struct {
	d   time.Duration
	err error
}

func (f fakeDelay) Delay(context.Context, string) (time.Duration, error) { return f.d, f.err }

type fakeNet struct {
	local, trusted       []netip.Addr
	localErr, trustedErr error
	dial                 func(addr string) (net.Conn, error)
	dialed               string
}

func (f *fakeNet) LookupLocal(context.Context, string) ([]netip.Addr, error) {
	return f.local, f.localErr
}
func (f *fakeNet) LookupTrusted(context.Context, string) ([]netip.Addr, error) {
	return f.trusted, f.trustedErr
}
func (f *fakeNet) Dial(_ context.Context, addr string) (net.Conn, error) {
	f.dialed = addr
	return f.dial(addr)
}

func ips(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func checker(n *fakeNet, d fakeDelay) *Checker {
	return &Checker{Net: n, Delayer: d, Now: func() time.Time { return t0 }, Timeout: time.Second}
}

func TestHealthyNodeNeedsOnlyTheEndToEndCheck(t *testing.T) {
	n := &fakeNet{dial: func(string) (net.Conn, error) { t.Fatal("healthy node must not be probed further"); return nil, nil }}
	c := checker(n, fakeDelay{d: 87 * time.Millisecond}).Check(context.Background(), Target{Name: "a", Server: "a.example.com", Port: 443})
	if !c.OK || c.DelayMs != 87 || c.Kind != KindNone {
		t.Errorf("check = %+v", c)
	}
}

func TestDNSPoisoningDetected(t *testing.T) {
	n := &fakeNet{local: ips("127.0.0.1"), trusted: ips("203.0.113.9")}
	c := checker(n, fakeDelay{err: errors.New("timeout")}).Check(context.Background(), Target{Name: "a", Server: "node.example.com", Port: 443})
	if c.OK || c.Kind != KindDNSPoison || c.Stage != "dns" || !c.Kind.Blocking() {
		t.Errorf("check = %+v", c)
	}
}

func TestCDNDifferencesAreNotPoisoning(t *testing.T) {
	k, _ := ClassifyDNS(ips("203.0.113.1"), nil, ips("203.0.113.9"), nil)
	if k != KindNone {
		t.Errorf("plausible different answers classified as %s", k)
	}
	k, _ = ClassifyDNS(ips("10.0.0.1"), nil, ips("10.0.0.1"), nil)
	if k != KindNone {
		t.Errorf("matching answers classified as %s", k)
	}
	k, _ = ClassifyDNS(nil, errors.New("nxdomain"), ips("203.0.113.9"), nil)
	if k != KindDNS {
		t.Errorf("local failure classified as %s", k)
	}
	k, _ = ClassifyDNS(ips("0.0.0.0"), nil, nil, errors.New("doh down"))
	if k != KindDNSPoison {
		t.Errorf("sinkhole answer with no trusted resolver classified as %s", k)
	}
}

func TestTCPFailuresClassified(t *testing.T) {
	cases := map[string]struct {
		err  error
		want Kind
	}{
		"reset":   {&net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, KindReset},
		"refused": {&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, KindRefused},
		"timeout": {context.DeadlineExceeded, KindTimeout},
		"other":   {errors.New("weird"), KindOther},
	}
	for name, tc := range cases {
		n := &fakeNet{dial: func(string) (net.Conn, error) { return nil, tc.err }}
		c := checker(n, fakeDelay{err: errors.New("down")}).Check(context.Background(), Target{Name: "a", Server: "192.0.2.1", Port: 443})
		if c.Kind != tc.want || c.Stage != "tcp" || !strings.Contains(c.Detail, "192.0.2.1:443") {
			t.Errorf("%s: check = %+v, want %s", name, c, tc.want)
		}
	}
	if !KindReset.Blocking() || KindTimeout.Blocking() || KindRefused.Blocking() {
		t.Error("only resets, TLS failures, and DNS poisoning count as blocking")
	}
}

func TestTLSHandshakeFailureAfterTCPSucceeds(t *testing.T) {
	n := &fakeNet{trusted: ips("203.0.113.9"), local: ips("203.0.113.9")}
	n.dial = func(addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { // a middlebox that resets once it sees the ClientHello
			buf := make([]byte, 1024)
			server.Read(buf)
			server.Close()
		}()
		return client, nil
	}
	c := checker(n, fakeDelay{err: errors.New("down")}).Check(context.Background(), Target{Name: "a", Server: "node.example.com", Port: 443, TLS: true, SNI: "front.example.com"})
	if c.Kind != KindTLS || c.Stage != "tls" || !strings.Contains(c.Detail, "front.example.com") {
		t.Errorf("check = %+v", c)
	}
	if n.dialed != "203.0.113.9:443" {
		t.Errorf("dialed %s; the trusted answer should be used", n.dialed)
	}
}

func TestProxyFailureWhenServerIsReachable(t *testing.T) {
	n := &fakeNet{dial: func(string) (net.Conn, error) { a, _ := net.Pipe(); return a, nil }}
	c := checker(n, fakeDelay{err: errors.New("bad credentials")}).Check(context.Background(), Target{Name: "a", Server: "192.0.2.1", Port: 8388})
	if c.Kind != KindProxy || c.Stage != "proxy" || !strings.Contains(c.Detail, "bad credentials") {
		t.Errorf("check = %+v", c)
	}
	udp := checker(n, fakeDelay{err: context.DeadlineExceeded}).Check(context.Background(), Target{Name: "h", Server: "192.0.2.1", Port: 443, UDP: true})
	if udp.Kind != KindTimeout {
		t.Errorf("UDP node check = %+v", udp)
	}
}

func TestTLSHandshakeSucceeding(t *testing.T) {
	// A real TLS server proves the handshake stage doesn't flag healthy servers.
	cert := selfSigned(t)
	client, server := net.Pipe()
	go func() { tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake() }()
	n := &fakeNet{dial: func(string) (net.Conn, error) { return client, nil }}
	c := checker(n, fakeDelay{err: errors.New("down")}).Check(context.Background(), Target{Name: "a", Server: "192.0.2.1", Port: 443, TLS: true})
	if c.Stage != "proxy" {
		t.Errorf("handshake should have succeeded: %+v", c)
	}
}

func TestSummaryStates(t *testing.T) {
	ok := func(min int) Check {
		return Check{Time: t0.Add(time.Duration(min) * time.Minute), Node: "n", OK: true, DelayMs: 100}
	}
	bad := func(min int, k Kind) Check {
		return Check{Time: t0.Add(time.Duration(min) * time.Minute), Node: "n", Kind: k, Detail: "boom"}
	}
	now := t0.Add(30 * time.Minute)
	cases := []struct {
		name string
		cs   []Check
		want State
	}{
		{"none", nil, StateUnknown},
		{"healthy", []Check{ok(0), ok(1), ok(2)}, StateHealthy},
		{"one failure", []Check{ok(0), ok(1), bad(2, KindTimeout)}, StateDegraded},
		{"recovered but flaky", []Check{ok(0), bad(1, KindTimeout), ok(2), bad(3, KindTimeout), ok(4)}, StateDegraded},
		{"down", []Check{ok(0), bad(1, KindTimeout), bad(2, KindTimeout)}, StateDown},
		{"blocked", []Check{ok(0), bad(1, KindReset), bad(2, KindReset)}, StateBlocked},
		{"tls blocked", []Check{bad(1, KindTLS), bad(2, KindTLS), bad(3, KindTLS)}, StateBlocked},
	}
	for _, tc := range cases {
		if got := Summarize("n", tc.cs, now); got.State != tc.want {
			t.Errorf("%s: state %s, want %s (%+v)", tc.name, got.State, tc.want, got)
		}
	}
	s := Summarize("n", []Check{ok(0), bad(1, KindReset), bad(2, KindReset)}, now)
	if !s.Since.Equal(t0.Add(time.Minute)) || s.Uptime24h < 0.33 || s.Uptime24h > 0.34 || s.AvgDelayMs != 100 || !strings.Contains(s.Reason, "2 checks in a row") {
		t.Errorf("summary = %+v", s)
	}
}

func TestHistoryRecordTrimPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h", "health.json")
	h := LoadHistory(path)
	now := time.Now()
	h.Now = func() time.Time { return now }
	h.Record(Check{Time: t0, Node: "old", OK: true}) // older than a week: trimmed
	h.Record(Check{Time: now.Add(-time.Hour), Node: "new", OK: true})
	for i := 0; i < maxPerNode+20; i++ {
		h.Record(Check{Time: now.Add(-time.Minute), Node: "busy", OK: true})
	}
	if got := h.Nodes(); fmt.Sprint(got) != "[busy new]" {
		t.Errorf("nodes = %v", got)
	}
	if n := len(h.Checks("busy")); n != maxPerNode {
		t.Errorf("busy has %d checks", n)
	}
	if err := h.Save(); err != nil {
		t.Fatal(err)
	}
	again := LoadHistory(path)
	again.Now = h.Now
	if len(again.Checks("new")) != 1 {
		t.Errorf("reloaded = %v", again.Nodes())
	}
	again.Forget(map[string]bool{"new": true})
	if fmt.Sprint(again.Nodes()) != "[new]" {
		t.Errorf("after Forget = %v", again.Nodes())
	}
	os.WriteFile(path, []byte("{garbage"), 0o600)
	if n := len(LoadHistory(path).Nodes()); n != 0 {
		t.Error("corrupt history should load empty")
	}
}

func TestOverview(t *testing.T) {
	down := func(n string, k Kind) Summary { return Summary{Node: n, State: StateDown, Kind: k} }
	up := Summary{Node: "ok", State: StateHealthy}
	if notes := Overview([]Summary{down("a", KindTimeout), down("b", KindTimeout)}); len(notes) == 0 || !strings.Contains(notes[0], "Every node is failing") {
		t.Errorf("all-down notes = %v", notes)
	}
	if notes := Overview([]Summary{down("a", KindReset), down("b", KindReset), up}); len(notes) == 0 || !strings.Contains(notes[0], "failing the same way") {
		t.Errorf("same-kind notes = %v", notes)
	}
	if notes := Overview([]Summary{up}); len(notes) != 0 {
		t.Errorf("notes = %v", notes)
	}
}

func TestTargetsFromConfig(t *testing.T) {
	cfg := `
proxies:
  - {name: ss1, type: ss, server: 192.0.2.1, port: 8388}
  - {name: tr1, type: trojan, server: t.example.com, port: "443", sni: front.example.com}
  - {name: vl1, type: vless, server: v.example.com, port: 443, reality-opts: {public-key: x}, servername: www.example.org}
  - {name: hy, type: hysteria2, server: h.example.com, port: 443}
  - {name: d, type: direct}
  - {type: ss, server: x, port: 1}
proxy-groups:
  - {name: g, type: select, proxies: [ss1]}
`
	ts, err := TargetsFromConfig([]byte(cfg))
	if err != nil || len(ts) != 4 {
		t.Fatalf("targets = %+v, %v", ts, err)
	}
	by := map[string]Target{}
	for _, x := range ts {
		by[x.Name] = x
	}
	if by["ss1"].TLS || !by["tr1"].TLS || by["tr1"].Port != 443 || by["tr1"].SNI != "front.example.com" {
		t.Errorf("ss1/tr1 = %+v / %+v", by["ss1"], by["tr1"])
	}
	if !by["vl1"].TLS || by["vl1"].SNI != "www.example.org" || !by["hy"].UDP || by["hy"].TLS {
		t.Errorf("vl1/hy = %+v / %+v", by["vl1"], by["hy"])
	}
	if _, err := TargetsFromConfig([]byte(": : :")); err == nil {
		t.Error("garbage config accepted")
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
