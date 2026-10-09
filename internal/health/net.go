package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// SysNet is the real Net. Its sockets are bound to the physical interface
// so checks measure the node's own path, not a trip through TUN.
type SysNet struct {
	// Interface is the physical interface to bind to; empty leaves
	// sockets unbound (used when TUN is off).
	Interface string
	// DoH is the trusted resolver's endpoint; it must be addressed by IP so
	// that finding it needs no DNS. Defaults to Cloudflare.
	DoH string
}

const defaultDoH = "https://1.1.1.1/dns-query"

func (n SysNet) control() func(network, address string, c syscall.RawConn) error {
	if n.Interface == "" {
		return nil
	}
	ifi, err := net.InterfaceByName(n.Interface)
	if err != nil {
		return func(string, string, syscall.RawConn) error { return err }
	}
	const ipBoundIf, ipv6BoundIf = 25, 125 // <netinet/in.h> on macOS
	return func(network, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIf, ifi.Index)
			} else {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIf, ifi.Index)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

func (n SysNet) dialer() *net.Dialer {
	return &net.Dialer{Timeout: 8 * time.Second, Control: n.control()}
}

// Dial implements Net.
func (n SysNet) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return n.dialer().DialContext(ctx, "tcp", addr)
}

// LookupLocal implements Net, using the system resolver.
func (n SysNet) LookupLocal(ctx context.Context, host string) ([]netip.Addr, error) {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return n.dialer().DialContext(ctx, network, address)
	}}
	return r.LookupNetIP(ctx, "ip", host)
}

// LookupTrusted implements Net with DNS-over-HTTPS (JSON API).
func (n SysNet) LookupTrusted(ctx context.Context, host string) ([]netip.Addr, error) {
	endpoint := n.DoH
	if endpoint == "" {
		endpoint = defaultDoH
	}
	var out []netip.Addr
	var firstErr error
	for _, typ := range []string{"A", "AAAA"} {
		addrs, err := n.dohQuery(ctx, endpoint, host, typ)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		out = append(out, addrs...)
	}
	if len(out) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, fmt.Errorf("no addresses for %s", host)
	}
	return out, nil
}

func (n SysNet) dohQuery(ctx context.Context, endpoint, host, typ string) ([]netip.Addr, error) {
	q := url.Values{"name": {host}, "type": {typ}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{
		DialContext: n.dialer().DialContext, DisableKeepAlives: true, Proxy: nil,
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("trusted resolver: " + resp.Status)
	}
	var body struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range body.Answer {
		if a.Type != 1 && a.Type != 28 { // A, AAAA (skip CNAME records)
			continue
		}
		if ip, err := netip.ParseAddr(a.Data); err == nil {
			out = append(out, ip)
		}
	}
	return out, nil
}
