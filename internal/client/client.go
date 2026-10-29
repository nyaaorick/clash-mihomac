// Package client calls the running daemon's localhost API. The CLI uses
// the full token; the MCP server uses the agent token.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Token files, by scope.
const (
	TokenFull  = "gui-token"
	TokenAgent = "mcp-token"
)

// Client talks to the daemon.
type Client struct {
	Base  string
	Token string
	HTTP  *http.Client
}

// ErrNotRunning means the daemon's state file is missing.
var ErrNotRunning = errors.New("Clash Mihomac is not running (start it with `mihomac start`)")

// Connect returns a client for the daemon whose data lives under home,
// using the named token file.
func Connect(home, tokenFile string) (*Client, error) {
	st, err := os.ReadFile(filepath.Join(home, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotRunning
	}
	if err != nil {
		return nil, err
	}
	var state struct {
		GUIURL string `json:"gui_url"`
	}
	if err := json.Unmarshal(st, &state); err != nil || state.GUIURL == "" {
		return nil, fmt.Errorf("state file is unreadable; stop and start Clash Mihomac")
	}
	data, err := os.ReadFile(filepath.Join(home, tokenFile))
	if err != nil {
		return nil, fmt.Errorf("read %s token: %w", tokenFile, err)
	}
	return &Client{
		Base:  strings.TrimSuffix(state.GUIURL, "/"),
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
		return fmt.Errorf("%s %s: %w (is Clash Mihomac running?)", method, path, err)
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
