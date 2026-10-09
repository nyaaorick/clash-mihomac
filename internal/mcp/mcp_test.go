package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type fakeAPI struct {
	posts []string
}

func (f *fakeAPI) Get(_ context.Context, path string, out any) error {
	switch {
	case strings.HasPrefix(path, "/api/connections/"):
		return json.Unmarshal([]byte(`{"explanation":{"summary":"curl connected to example.com:443."}}`), out)
	default:
		return json.Unmarshal([]byte(`{"mode":"tun"}`), out)
	}
}

func (f *fakeAPI) Post(_ context.Context, path string, body, out any) error {
	data, _ := json.Marshal(body)
	f.posts = append(f.posts, path+" "+string(data))
	return json.Unmarshal([]byte(`{"id":"ab12","diff":"+ domain-suffix x.com → DIRECT\n","verdict":"Both paths work."}`), out)
}

func run(t *testing.T, api API, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	s := &Server{API: api, Instance: "debug", Version: "test"}
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var resps []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("bad response %q", l)
		}
		resps = append(resps, m)
	}
	return resps
}

func TestHandshakeAndToolList(t *testing.T) {
	resps := run(t, &fakeAPI{},
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"bogus"}`,
	)
	if len(resps) != 3 {
		t.Fatalf("got %d responses, want 3 (notification must not be answered)", len(resps))
	}
	if v := resps[0]["result"].(map[string]any)["protocolVersion"]; v != "2025-03-26" {
		t.Errorf("protocolVersion = %v", v)
	}
	list := resps[1]["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, tl := range list {
		names[tl.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"list_connections", "inspect_connection", "propose_rule_change", "probe_url"} {
		if !names[want] {
			t.Errorf("missing tool %s", want)
		}
	}
	if resps[2]["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Errorf("unknown method error = %v", resps[2]["error"])
	}
}

func TestProposeIsDryRun(t *testing.T) {
	api := &fakeAPI{}
	resps := run(t, api, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"propose_rule_change","arguments":{"summary":"bypass x","add":[{"type":"domain-suffix","value":"x.com","target":"DIRECT"}]}}}`)
	text := resps[0]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "Proposal ab12") || !strings.Contains(text, "mihomac proposals apply ab12") {
		t.Errorf("text = %s", text)
	}
	if len(api.posts) != 1 || !strings.HasPrefix(api.posts[0], "/api/proposals ") {
		t.Errorf("posts = %v, want only /api/proposals", api.posts)
	}
}

func TestInspectLeadsWithExplanation(t *testing.T) {
	resps := run(t, &fakeAPI{}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"inspect_connection","arguments":{"id":"abc"}}}`)
	text := resps[0]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.HasPrefix(text, "curl connected to example.com:443.") {
		t.Errorf("text = %s", text)
	}
}
