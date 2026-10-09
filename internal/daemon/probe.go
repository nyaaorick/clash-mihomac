package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Attempt is one fetch of the probe URL.
type Attempt struct {
	OK     bool   `json:"ok"`
	Status int    `json:"status,omitempty"`
	Millis int64  `json:"millis"`
	Error  string `json:"error,omitempty"`
}

// ProbeResult compares fetching a URL directly with fetching it through
// the proxy, to tell whether Clash Mihomac is the cause of a problem.
type ProbeResult struct {
	URL             string  `json:"url"`
	DirectInterface string  `json:"direct_interface"`
	Direct          Attempt `json:"direct"`
	Proxied         Attempt `json:"proxied"`
	Verdict         string  `json:"verdict"`
}

// Probe fetches rawURL twice at the same time: once bound to the physical
// interface iface, which bypasses every TUN device (the same effect as
// temporarily turning TUN off, without touching anyone else's traffic),
// and once through the instance's mixed-port.
func Probe(ctx context.Context, rawURL string, proxyPort int, iface string) (ProbeResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ProbeResult{}, fmt.Errorf("probe needs an http(s) URL, got %q", rawURL)
	}
	res := ProbeResult{URL: u.String(), DirectInterface: iface}

	direct, err := boundTransport(iface)
	if err != nil {
		return ProbeResult{}, err
	}
	proxyURL := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", proxyPort)}
	proxied := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); res.Direct = fetch(ctx, direct, u.String()) }()
	go func() { defer wg.Done(); res.Proxied = fetch(ctx, proxied, u.String()) }()
	wg.Wait()

	switch {
	case res.Direct.OK && res.Proxied.OK:
		res.Verdict = "Both paths work, so Clash Mihomac isn't blocking this URL. If an app still fails, look at the app or its own proxy settings."
	case res.Direct.OK:
		res.Verdict = "The direct path works but the proxied path fails: the cause is on the proxy path (the matching rule, the node, or the core). Check the connection's diagnostics."
	case res.Proxied.OK:
		res.Verdict = "Only the proxied path works: this site is unreachable on your direct network, which is what the proxy is for. Clash Mihomac isn't the problem."
	default:
		res.Verdict = "Both paths fail: the problem is upstream (the site, DNS, or your network), not Clash Mihomac."
	}
	return res, nil
}

func fetch(ctx context.Context, rt http.RoundTripper, u string) Attempt {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Attempt{Error: err.Error()}
	}
	req.Header.Set("User-Agent", "mihomac-probe")
	resp, err := (&http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	a := Attempt{Millis: time.Since(start).Milliseconds()}
	if err != nil {
		a.Error = err.Error()
		return a
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	a.Status = resp.StatusCode
	a.OK = resp.StatusCode < 500
	return a
}

// boundTransport returns a transport whose sockets, including DNS, are
// bound to iface with IP_BOUND_IF so they skip TUN routes.
func boundTransport(iface string) (*http.Transport, error) {
	if iface == "" {
		return nil, errors.New("no physical default interface found")
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	const ipBoundIf, ipv6BoundIf = 25, 125 // <netinet/in.h>
	control := func(network, _ string, c syscall.RawConn) error {
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
	dnsDialer := &net.Dialer{Timeout: 5 * time.Second, Control: control}
	dialer := &net.Dialer{
		Timeout: 8 * time.Second,
		Control: control,
		Resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dnsDialer.DialContext(ctx, network, address)
		}},
	}
	return &http.Transport{Proxy: nil, DialContext: dialer.DialContext, DisableKeepAlives: true}, nil
}
