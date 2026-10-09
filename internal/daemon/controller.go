package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// controller talks to mihomo's external controller.
type controller struct {
	addr   string
	secret string
}

var ctrlClient = &http.Client{Timeout: 5 * time.Second}

func (c controller) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+c.addr+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	resp, err := ctrlClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("controller %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c controller) version(ctx context.Context) (string, error) {
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

func (c controller) connections(ctx context.Context) ([]ctrlConn, error) {
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

func (c controller) rules(ctx context.Context) ([]ctrlRule, error) {
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

func (c controller) proxies(ctx context.Context) (map[string]ctrlProxy, error) {
	var body struct {
		Proxies map[string]ctrlProxy `json:"proxies"`
	}
	err := c.do(ctx, http.MethodGet, "/proxies", nil, &body)
	return body.Proxies, err
}

// reload makes mihomo re-read its config file.
func (c controller) reload(ctx context.Context, path string) error {
	return c.do(ctx, http.MethodPut, "/configs?force=true", map[string]string{"path": path}, nil)
}

// streamLogs calls fn for each log line until ctx is cancelled or the
// stream ends.
func (c controller) streamLogs(ctx context.Context, level string, fn func(level, payload string)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+c.addr+"/logs?level="+level, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	resp, err := http.DefaultClient.Do(req) // no timeout: this stream is long-lived
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

func (c controller) waitReady(ctx context.Context, exited <-chan struct{}, timeout time.Duration) error {
	deadline := time.After(timeout)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := c.version(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-exited:
			return errors.New("mihomo exited during startup")
		case <-deadline:
			return errors.New("mihomo controller not ready in time")
		case <-tick.C:
		}
	}
}
