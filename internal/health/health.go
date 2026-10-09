// Package health checks whether proxy nodes work, tells apart the ways a
// node can be blocked, and keeps a history of the results.
//
// A cheap end-to-end check runs often. Only when it fails does the checker
// look closer, stage by stage (DNS, TCP, TLS), because the stage that
// fails says what kind of blocking is happening:
//
//   - DNS poisoning: the system resolver returns different, bogus addresses
//     than a trusted resolver does for the node's hostname
//   - TCP reset or timeout: the node's address or port is blocked
//   - TLS handshake failure after TCP succeeds: the handshake is being
//     reset or dropped (typically filtering on the SNI)
//
// Everything that touches the network goes through the Net and Delayer
// interfaces, so the logic here is tested with fakes.
package health

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

// Kind says how a check failed.
type Kind string

// Failure kinds, from most to least specific.
const (
	KindNone      Kind = ""
	KindDNSPoison Kind = "dns-poisoning"
	KindDNS       Kind = "dns-failure"
	KindRefused   Kind = "tcp-refused"
	KindReset     Kind = "tcp-reset"
	KindTimeout   Kind = "timeout"
	KindTLS       Kind = "tls-handshake"
	KindProxy     Kind = "proxy-failed" // the server is reachable but the proxy path doesn't work
	KindOther     Kind = "other"
)

// Blocking reports whether a failure kind looks like interference on the
// path rather than a node that is simply down.
func (k Kind) Blocking() bool {
	switch k {
	case KindDNSPoison, KindReset, KindTLS:
		return true
	}
	return false
}

// Target is a proxy node as the checker needs to know it.
type Target struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Server string `json:"server"`
	Port   int    `json:"port"`
	TLS    bool   `json:"tls"`
	SNI    string `json:"sni,omitempty"`
	UDP    bool   `json:"udp,omitempty"` // QUIC-style nodes: no TCP stages to test
}

// hostPort is the node's address as dialed.
func (t Target) hostPort() string { return net.JoinHostPort(t.Server, strconv.Itoa(t.Port)) }

// Check is the result of one health check of one node.
type Check struct {
	Time    time.Time `json:"time"`
	Node    string    `json:"node"`
	OK      bool      `json:"ok"`
	DelayMs int       `json:"delay_ms,omitempty"`
	Kind    Kind      `json:"kind,omitempty"`
	Stage   string    `json:"stage,omitempty"` // dns, tcp, tls, or proxy
	Detail  string    `json:"detail,omitempty"`
}

// Net is the network access the checker needs. Real implementations bind
// to the physical interface so checks don't loop through TUN.
type Net interface {
	// LookupLocal resolves host with the system resolver.
	LookupLocal(ctx context.Context, host string) ([]netip.Addr, error)
	// LookupTrusted resolves host over an encrypted resolver the local
	// network can't tamper with.
	LookupTrusted(ctx context.Context, host string) ([]netip.Addr, error)
	// Dial opens a TCP connection to addr (host:port).
	Dial(ctx context.Context, addr string) (net.Conn, error)
}

// Delayer measures end-to-end latency through a node (mihomo's delay test).
type Delayer interface {
	Delay(ctx context.Context, node string) (time.Duration, error)
}

// Checker runs health checks.
type Checker struct {
	Net     Net
	Delayer Delayer
	Now     func() time.Time
	Timeout time.Duration // per stage; default 6s
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Checker) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 6 * time.Second
}

// Check tests one node. A passing end-to-end delay test is enough; a
// failing one triggers the stage-by-stage diagnosis.
func (c *Checker) Check(ctx context.Context, t Target) Check {
	res := Check{Time: c.now(), Node: t.Name}
	d, err := c.Delayer.Delay(ctx, t.Name)
	if err == nil {
		res.OK, res.DelayMs = true, int(d/time.Millisecond)
		return res
	}
	res.Stage, res.Kind, res.Detail = c.diagnose(ctx, t, err)
	return res
}

// diagnose finds which stage fails. e2e is the error from the end-to-end test.
func (c *Checker) diagnose(ctx context.Context, t Target, e2e error) (stage string, kind Kind, detail string) {
	if t.Server == "" || t.Port == 0 || t.UDP {
		return "proxy", classifyE2E(e2e), "end-to-end test failed: " + e2e.Error()
	}
	host := t.Server
	if _, err := netip.ParseAddr(host); err != nil { // a name, not an address
		sctx, cancel := context.WithTimeout(ctx, c.timeout())
		local, lerr := c.Net.LookupLocal(sctx, host)
		cancel()
		sctx, cancel = context.WithTimeout(ctx, c.timeout())
		trusted, terr := c.Net.LookupTrusted(sctx, host)
		cancel()
		if k, why := ClassifyDNS(local, lerr, trusted, terr); k != KindNone {
			return "dns", k, why
		}
		// Prefer the trusted answer for the next stages so a poisoned
		// local resolver can't hide a node problem behind its own.
		if terr == nil && len(trusted) > 0 {
			host = trusted[0].String()
		} else if lerr == nil && len(local) > 0 {
			host = local[0].String()
		}
	}

	dctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	conn, err := c.Net.Dial(dctx, net.JoinHostPort(host, strconv.Itoa(t.Port)))
	if err != nil {
		return "tcp", ClassifyError(err), "connect to " + t.hostPort() + ": " + err.Error()
	}
	defer conn.Close()

	if t.TLS {
		conn.SetDeadline(time.Now().Add(c.timeout()))
		sni := t.SNI
		if sni == "" {
			sni = t.Server
		}
		// Only whether the handshake completes matters, not the certificate
		// (Reality and self-signed nodes are normal).
		tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true}) //nolint:gosec
		if err := tc.HandshakeContext(ctx); err != nil {
			k := ClassifyError(err)
			if k == KindOther || k == KindTimeout || k == KindReset {
				k = KindTLS
			}
			return "tls", k, "TLS handshake with " + t.hostPort() + " (SNI " + sni + "): " + err.Error()
		}
	}
	return "proxy", KindProxy, "the server accepts connections but traffic through the node fails: " + e2e.Error()
}

// classifyE2E labels a failed end-to-end test that couldn't be narrowed down.
func classifyE2E(err error) Kind {
	if k := ClassifyError(err); k == KindTimeout {
		return KindTimeout
	}
	return KindProxy
}

// ClassifyError maps a network error to a Kind.
func ClassifyError(err error) Kind {
	var dnsErr *net.DNSError
	switch {
	case err == nil:
		return KindNone
	case errors.Is(err, syscall.ECONNREFUSED):
		return KindRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return KindReset
	case errors.As(err, &dnsErr):
		return KindDNS
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return KindTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return KindTimeout
	}
	// TLS libraries sometimes report a reset only as text.
	if msg := strings.ToLower(err.Error()); strings.Contains(msg, "connection reset") || strings.Contains(msg, "unexpected eof") || strings.Contains(msg, "eof") && strings.Contains(msg, "tls") {
		return KindReset
	}
	return KindOther
}

// ClassifyDNS compares what the system resolver and a trusted resolver say
// about a hostname. The answer is poisoned when the system's addresses
// don't overlap the trusted ones and look forged: unspecified, loopback,
// private, or otherwise unroutable, which is what poisoning injects.
func ClassifyDNS(local []netip.Addr, lerr error, trusted []netip.Addr, terr error) (Kind, string) {
	switch {
	case lerr != nil && terr != nil:
		return KindDNS, "neither the system resolver nor the trusted resolver can resolve the name: " + lerr.Error()
	case lerr != nil:
		return KindDNS, "the system resolver fails but the trusted resolver works: " + lerr.Error()
	case terr != nil || len(trusted) == 0:
		// Without a trusted answer, forged addresses are still telling.
		for _, a := range local {
			if forged(a) {
				return KindDNSPoison, fmt.Sprintf("the system resolver returned %s, which can't be a real public address", a)
			}
		}
		return KindNone, ""
	}
	if overlaps(local, trusted) {
		return KindNone, ""
	}
	for _, a := range local {
		if forged(a) {
			return KindDNSPoison, fmt.Sprintf("the system resolver returned %s but the trusted resolver returned %s", local[0], trusted[0])
		}
	}
	// Different but plausible answers are usually CDN/geo-DNS, not poisoning.
	return KindNone, ""
}

func overlaps(a, b []netip.Addr) bool {
	for _, x := range a {
		for _, y := range b {
			if x.Unmap() == y.Unmap() {
				return true
			}
		}
	}
	return false
}

// forged reports addresses that a public hostname should never resolve to.
func forged(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsMulticast() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(a) || netip.MustParsePrefix("198.18.0.0/15").Contains(a)
}

// TargetsFromConfig reads the proxy nodes out of a mihomo config.
func TargetsFromConfig(cfg []byte) ([]Target, error) {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(cfg, &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var out []Target
	for _, p := range doc.Proxies {
		name, _ := p["name"].(string)
		if name == "" {
			continue
		}
		t := Target{Name: name}
		t.Type, _ = p["type"].(string)
		t.Server, _ = p["server"].(string)
		switch v := p["port"].(type) {
		case int:
			t.Port = v
		case string:
			t.Port, _ = strconv.Atoi(v)
		}
		if t.Type == "direct" || t.Type == "dns" || t.Server == "" {
			continue
		}
		tlsOn, _ := p["tls"].(bool)
		t.TLS = tlsOn || t.Type == "trojan" || p["reality-opts"] != nil
		for _, k := range []string{"servername", "sni"} {
			if s, ok := p[k].(string); ok && s != "" {
				t.SNI = s
			}
		}
		// QUIC/UDP based nodes can't be probed with a TCP connect.
		switch t.Type {
		case "hysteria", "hysteria2", "tuic", "wireguard":
			t.UDP, t.TLS = true, false
		}
		out = append(out, t)
	}
	return out, nil
}
