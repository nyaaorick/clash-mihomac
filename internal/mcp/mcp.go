// Package mcp is Clash Mihomac's Model Context Protocol server.
//
// It speaks JSON-RPC 2.0 over stdio (one message per line) and exposes the
// instance's API to AI assistants with the agent token: every read tool,
// plus propose_rule_change, which only records a dry-run proposal. Applying
// a proposal needs a person, in the GUI or with `mihomac proposals apply`.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"sync"
)

// API is the subset of client.Client the server needs.
type API interface {
	Get(ctx context.Context, path string, out any) error
	Post(ctx context.Context, path string, body, out any) error
}

// Server serves MCP for one instance.
type Server struct {
	API      API
	Instance string
	Version  string
}

var protocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads requests from in and writes responses to out until in ends.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	var mu sync.Mutex
	enc := json.NewEncoder(out)
	write := func(r response) {
		mu.Lock()
		defer mu.Unlock()
		enc.Encode(r)
	}
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			write(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
			continue
		}
		if len(req.ID) == 0 {
			continue // notification, e.g. notifications/initialized
		}
		result, rerr := s.handle(ctx, req)
		write(response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr})
	}
	return sc.Err()
}

func (s *Server) handle(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &p)
		version := protocolVersions[0]
		if slices.Contains(protocolVersions, p.ProtocolVersion) {
			version = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "clash-mihomac", "version": s.Version},
			"instructions": "Clash Mihomac routes this Mac's traffic through mihomo. Use the read tools to see where connections go and why " +
				"(inspect_connection explains a single request), probe_url to check whether the proxy is the cause of a failure, and " +
				"propose_rule_change to suggest a fix. Proposals are dry runs: tell the user the proposal ID and that they must apply it " +
				"themselves in the GUI or with `mihomac proposals apply <id>`.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		text, err := s.call(ctx, p.Name, p.Arguments)
		if err != nil {
			return toolResult(err.Error(), true), nil
		}
		return toolResult(text, false), nil
	}
	return nil, &rpcError{-32601, "method not found: " + req.Method}
}

func toolResult(text string, isError bool) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isError}
}

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

func schema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

var readOnly = map[string]any{"readOnlyHint": true}

var ruleSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"type":   map[string]any{"type": "string", "enum": []string{"domain", "domain-suffix", "domain-keyword", "ip-cidr", "process-name", "process-path", "app"}},
		"value":  map[string]any{"type": "string", "description": "Domain, CIDR, process name, absolute process path, or absolute path to a .app bundle"},
		"target": map[string]any{"type": "string", "description": "DIRECT, REJECT, a proxy or group name from list_nodes, or iface:<name> (e.g. iface:en1) to go direct out a specific interface"},
		"note":   map[string]any{"type": "string"},
	},
	"required":             []string{"type", "value", "target"},
	"additionalProperties": false,
}

var tools = []tool{
	{"network_status", "Mode (TUN, system proxy, or port-only), core version, helper availability, rule counts, and recent events.", schema(map[string]any{}), readOnly},
	{"list_connections", "Recent and live connections, newest first: app, destination, matched rule, and route. Filter with a substring of host, IP, app, rule, or node.",
		schema(map[string]any{
			"query": map[string]any{"type": "string"},
			"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 500},
		}), readOnly},
	{"inspect_connection", "Explain one connection end to end (app → rule and where it came from → outbound node/interface → destination), with related core log lines.",
		schema(map[string]any{"id": map[string]any{"type": "string"}}, "id"), readOnly},
	{"list_rules", "The final rule list in match order, each with its source (user rule, built-in bypass, rule pack, or config file), plus the user's rule set and available packs.", schema(map[string]any{}), readOnly},
	{"list_nodes", "Proxies and proxy groups, with each group's current selection and latest latency.", schema(map[string]any{}), readOnly},
	{"list_interfaces", "Network interfaces with addresses, route counts, and roles (default route, VPN, this instance's TUN).", schema(map[string]any{}), readOnly},
	{"probe_url", "Fetch a URL directly (bypassing every TUN) and through the proxy at the same time, and say whether the proxy is the cause of a failure.",
		schema(map[string]any{"url": map[string]any{"type": "string", "description": "http:// or https:// URL"}}, "url"), readOnly},
	{"propose_rule_change", "Propose a rule change as a dry run. Returns a diff and a proposal ID; nothing changes until the user applies it.",
		schema(map[string]any{
			"summary":       map[string]any{"type": "string", "description": "One sentence on why, shown to the user"},
			"add":           map[string]any{"type": "array", "items": ruleSchema, "description": "Rules to add; they take precedence over existing rules"},
			"remove":        map[string]any{"type": "array", "items": ruleSchema, "description": "Existing user rules to remove (matched on type, value, target)"},
			"enable_packs":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"disable_packs": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "summary"), map[string]any{"readOnlyHint": false, "destructiveHint": false}},
	{"list_proposals", "Rule-change proposals and whether they were applied, rejected, or are still pending.", schema(map[string]any{}), readOnly},
}

func (s *Server) call(ctx context.Context, name string, raw json.RawMessage) (string, error) {
	var args map[string]any
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", fmt.Errorf("invalid arguments: %w", err)
		}
	}
	str := func(k string) string { v, _ := args[k].(string); return v }

	var out any
	var err error
	switch name {
	case "network_status":
		err = s.API.Get(ctx, "/api/status", &out)
	case "list_connections":
		limit := 50
		if f, ok := args["limit"].(float64); ok {
			limit = int(f)
		}
		err = s.API.Get(ctx, "/api/connections?q="+url.QueryEscape(str("query"))+"&limit="+strconv.Itoa(limit), &out)
	case "inspect_connection":
		if str("id") == "" {
			return "", fmt.Errorf("id is required")
		}
		var rawDetail json.RawMessage
		if err = s.API.Get(ctx, "/api/connections/"+url.PathEscape(str("id")), &rawDetail); err != nil {
			return "", err
		}
		var detail struct {
			Explanation struct {
				Summary string `json:"summary"`
			} `json:"explanation"`
		}
		json.Unmarshal(rawDetail, &detail)
		return detail.Explanation.Summary + "\n\n" + indent(rawDetail), nil
	case "list_rules":
		err = s.API.Get(ctx, "/api/rules", &out)
	case "list_nodes":
		err = s.API.Get(ctx, "/api/nodes", &out)
	case "list_interfaces":
		err = s.API.Get(ctx, "/api/interfaces", &out)
	case "probe_url":
		var rawRes json.RawMessage
		if err = s.API.Post(ctx, "/api/probe", map[string]string{"url": str("url")}, &rawRes); err != nil {
			return "", err
		}
		var res struct {
			Verdict string `json:"verdict"`
		}
		json.Unmarshal(rawRes, &res)
		return res.Verdict + "\n\n" + indent(rawRes), nil
	case "propose_rule_change":
		change := map[string]any{}
		for _, k := range []string{"add", "remove", "enable_packs", "disable_packs"} {
			if v, ok := args[k]; ok {
				change[k] = v
			}
		}
		var p struct {
			ID   string `json:"id"`
			Diff string `json:"diff"`
		}
		if err = s.API.Post(ctx, "/api/proposals", map[string]any{"summary": str("summary"), "change": change}, &p); err != nil {
			return "", err
		}
		return fmt.Sprintf("Proposal %s recorded (dry run, nothing changed yet):\n\n%s\nThe user must apply it in the Clash Mihomac GUI (Rules tab) or run:\n  mihomac proposals apply %s --instance %s",
			p.ID, p.Diff, p.ID, s.Instance), nil
	case "list_proposals":
		err = s.API.Get(ctx, "/api/proposals", &out)
	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
	if err != nil {
		return "", err
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	return truncate(string(data)), nil
}

func indent(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	data, _ := json.MarshalIndent(v, "", "  ")
	return truncate(string(data))
}

func truncate(s string) string {
	const max = 60 << 10
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n… (truncated; narrow the query)"
}
