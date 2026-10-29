package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/verge"
)

// controller talks to mihomo's external controller, over the Unix socket
// Verge configures by default or over TCP when that is what Verge has.
// The endpoint can change while the daemon runs (Verge regenerates its
// config on every apply), so it is swapped under a lock.
type controller struct {
	mu     sync.Mutex
	ep     verge.Endpoint
	client *http.Client // short requests
	stream *http.Client // the log stream: no timeout
}

// newController returns a controller for ep.
func newController(ep verge.Endpoint) *controller {
	c := &controller{}
	c.set(ep)
	return c
}

// set switches the controller to ep.
func (c *controller) set(ep verge.Endpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ep == ep && c.client != nil {
		return
	}
	if c.client != nil {
		if old, ok := c.client.Transport.(*http.Transport); ok {
			old.CloseIdleConnections()
		}
	}
	c.ep = ep
	tr := &http.Transport{Proxy: nil, IdleConnTimeout: 30 * time.Second}
	if ep.Network == "unix" {
		path := ep.Address
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}
	}
	c.client = &http.Client{Timeout: 5 * time.Second, Transport: tr}
	c.stream = &http.Client{Transport: tr}
}

// snapshot returns the endpoint with the clients built for it, taken
// under one lock so a swap can't pair one endpoint's URL with another's
// transport.
func (c *controller) snapshot() (verge.Endpoint, *http.Client, *http.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ep, c.client, c.stream
}

// endpoint returns the current endpoint.
func (c *controller) endpoint() verge.Endpoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ep
}

// ready reports whether an endpoint is configured.
func (c *controller) ready() bool { return c.endpoint().Network != "" }

func urlFor(ep verge.Endpoint, path string) string {
	if ep.Network == "unix" {
		return "http://mihomo" + path
	}
	return "http://" + ep.Address + path
}

// newRequest builds a request for the current endpoint and returns the
// clients that go with it.
func (c *controller) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, *http.Client, *http.Client, error) {
	ep, client, stream := c.snapshot()
	if ep.Network == "" {
		return nil, nil, nil, errors.New("mihomo controller not configured")
	}
	req, err := http.NewRequestWithContext(ctx, method, urlFor(ep, path), body)
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+ep.Secret)
	return req, client, stream, nil
}

// do sends a short request. slow uses the client without a timeout, for
// calls that legitimately take a while (a full config reload); the
// caller's context bounds those.
func (c *controller) do(ctx context.Context, method, path string, body, out any) error {
	return c.doWith(ctx, false, method, path, body, out)
}

func (c *controller) doWith(ctx context.Context, slow bool, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	req, client, stream, err := c.newRequest(ctx, method, path, r)
	if err != nil {
		return err
	}
	if slow {
		client = stream
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return &ctrlHTTPError{Method: method, Path: path, Status: resp.StatusCode, Msg: firstNonEmpty(strings.TrimSpace(string(msg)), resp.Status)}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// ctrlHTTPError is a reply mihomo gave, as opposed to not being reachable.
type ctrlHTTPError struct {
	Method, Path string
	Status       int
	Msg          string
}

func (e *ctrlHTTPError) Error() string {
	return fmt.Sprintf("controller %s %s: %d: %s", e.Method, e.Path, e.Status, e.Msg)
}

func (c *controller) version(ctx context.Context) (string, error) {
	var body struct {
		Version string `json:"version"`
	}
	err := c.do(ctx, http.MethodGet, "/version", nil, &body)
	return body.Version, err
}

// ctrlConn is one entry of mihomo's GET /connections.
type ctrlConn struct {
	ID       string `json:"id"`
	Metadata struct {
		Network         string `json:"network"`
		Type            string `json:"type"`
		SourceIP        string `json:"sourceIP"`
		SourcePort      string `json:"sourcePort"`
		DestinationIP   string `json:"destinationIP"`
		DestinationPort string `json:"destinationPort"`
		Host            string `json:"host"`
		SniffHost       string `json:"sniffHost"`
		Process         string `json:"process"`
		ProcessPath     string `json:"processPath"`
		RemoteDest      string `json:"remoteDestination"`
		InboundName     string `json:"inboundName"`
	} `json:"metadata"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Start       time.Time `json:"start"`
	Chains      []string  `json:"chains"`
	Rule        string    `json:"rule"`
	RulePayload string    `json:"rulePayload"`
}

func (c *controller) connections(ctx context.Context) ([]ctrlConn, error) {
	var body struct {
		Connections []ctrlConn `json:"connections"`
	}
	err := c.do(ctx, http.MethodGet, "/connections", nil, &body)
	return body.Connections, err
}

// ctrlRule is one entry of mihomo's GET /rules, in match order.
type ctrlRule struct {
	Index   int    `json:"index"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
}

func (c *controller) rules(ctx context.Context) ([]ctrlRule, error) {
	var body struct {
		Rules []ctrlRule `json:"rules"`
	}
	err := c.do(ctx, http.MethodGet, "/rules", nil, &body)
	return body.Rules, err
}

// ctrlProxy is one entry of mihomo's GET /proxies.
type ctrlProxy struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Now     string   `json:"now,omitempty"`
	All     []string `json:"all,omitempty"`
	Alive   bool     `json:"alive"`
	History []struct {
		Time  time.Time `json:"time"`
		Delay int       `json:"delay"`
	} `json:"history"`
}

func (c *controller) proxies(ctx context.Context) (map[string]ctrlProxy, error) {
	var body struct {
		Proxies map[string]ctrlProxy `json:"proxies"`
	}
	err := c.do(ctx, http.MethodGet, "/proxies", nil, &body)
	return body.Proxies, err
}

// delay runs mihomo's own delay test through one proxy.
func (c *controller) delay(ctx context.Context, proxy, url string, timeout time.Duration) (time.Duration, error) {
	q := neturl.Values{"url": {url}, "timeout": {strconv.Itoa(int(timeout / time.Millisecond))}}
	var body struct {
		Delay int `json:"delay"`
	}
	// The controller's own client times out at 5s; give the test its full timeout.
	req, short, _, err := c.newRequest(ctx, http.MethodGet, "/proxies/"+neturl.PathEscape(proxy)+"/delay?"+q.Encode(), nil)
	if err != nil {
		return 0, err
	}
	client := &http.Client{Timeout: timeout + 3*time.Second, Transport: short.Transport}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, fmt.Errorf("delay test: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, err
	}
	return time.Duration(body.Delay) * time.Millisecond, nil
}

// mode reads the core's running mode (rule, global, direct).
func (c *controller) mode(ctx context.Context) (string, error) {
	var body struct {
		Mode string `json:"mode"`
	}
	err := c.do(ctx, http.MethodGet, "/configs", nil, &body)
	return body.Mode, err
}

// setMode switches the core's mode in place.
func (c *controller) setMode(ctx context.Context, mode string) error {
	return c.do(ctx, http.MethodPatch, "/configs", map[string]string{"mode": mode}, nil)
}

// reloadPayload hands mihomo a whole new config to switch to in place.
// Nothing on disk changes: this is how Clash Mihomac's rules reach the
// running core right away, ahead of Verge's next apply.
func (c *controller) reloadPayload(ctx context.Context, cfg []byte) error {
	return c.doWith(ctx, true, http.MethodPut, "/configs?force=true", map[string]string{"payload": string(cfg)}, nil)
}

// streamLogs calls fn for each log line until ctx is cancelled or the
// stream ends.
func (c *controller) streamLogs(ctx context.Context, level string, fn func(level, payload string)) error {
	req, _, stream, err := c.newRequest(ctx, http.MethodGet, "/logs?level="+level, nil)
	if err != nil {
		return err
	}
	resp, err := stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("logs: " + resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var line struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
		}
		if json.Unmarshal(sc.Bytes(), &line) == nil {
			fn(line.Type, line.Payload)
		}
	}
	return sc.Err()
}

// tcpController is a test helper: a controller for a plain host:port.
func tcpController(addr, secret string) *controller {
	return newController(verge.Endpoint{Network: "tcp", Address: addr, Secret: secret})
}
