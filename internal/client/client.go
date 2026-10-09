// Package client calls a running instance's localhost API. The CLI uses
// the full token; the MCP server uses the agent token.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/instance"
)

// Token files, by scope.
const (
	TokenFull  = "gui-token"
	TokenAgent = "mcp-token"
)

// Client talks to one instance.
type Client struct {
	Base  string
	Token string
	HTTP  *http.Client
}

// ForInstance returns a client for inst using the named token file.
func ForInstance(inst instance.Instance, tokenFile string) (*Client, error) {
	data, err := os.ReadFile(inst.Path(tokenFile))
	if err != nil {
		return nil, fmt.Errorf("read %s token (is %s running?): %w", tokenFile, inst.Name, err)
	}
	return &Client{
		Base:  fmt.Sprintf("http://127.0.0.1:%d", inst.GUIPort),
		Token: strings.TrimSpace(string(data)),
		HTTP:  &http.Client{Timeout: 90 * time.Second},
	}, nil
}

// Get fetches path into out.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// Post sends body to path and decodes the reply into out.
func (c *Client) Post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Mihomac", "1")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w (is the instance running?)", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
