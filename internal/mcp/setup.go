package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ServerName is the name MCP clients list this server under.
const ServerName = "mihomac"

// ClientConfig renders the JSON snippet that registers the server with
// MCP clients that read an "mcpServers" object (Claude Desktop, Cursor,
// and most others). The server finds its own token on disk, so the
// snippet holds no secrets.
func ClientConfig(exe, instance string) string {
	cfg := map[string]any{"mcpServers": map[string]any{
		ServerName + "-" + instance: map[string]any{
			"command": exe,
			"args":    []string{"mcp", "--instance", instance},
		},
	}}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	return string(data)
}

// SetupInstructions explains how to connect common MCP clients.
func SetupInstructions(exe, instance string) string {
	name := ServerName + "-" + instance
	var b strings.Builder
	fmt.Fprintf(&b, "The MCP server runs over stdio and talks to the running %q instance on 127.0.0.1\n", instance)
	fmt.Fprint(&b, "using a read-only agent token that is read from disk; start the instance first.\n\n")
	fmt.Fprintf(&b, "Claude Code:\n  claude mcp add %s -- %s mcp --instance %s\n\n", name, exe, instance)
	fmt.Fprint(&b, "Claude Desktop, Cursor, and other clients: add this to the client's MCP config\n")
	fmt.Fprint(&b, "(Claude Desktop: claude_desktop_config.json; Cursor: ~/.cursor/mcp.json):\n\n")
	b.WriteString(ClientConfig(exe, instance))
	b.WriteString("\n\nAvailable tools are read-only, except propose_rule_change, which only records a\n")
	b.WriteString("dry-run diff. A person applies or rejects it in the GUI (Rules tab) or with\n")
	b.WriteString("`mihomac proposals`.\n")
	return b.String()
}
