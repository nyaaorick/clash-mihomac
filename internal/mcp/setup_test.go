package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClientConfigIsValidJSON(t *testing.T) {
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(ClientConfig("/usr/local/bin/mihomac")), &cfg); err != nil {
		t.Fatal(err)
	}
	s, ok := cfg.MCPServers["mihomac"]
	if !ok || s.Command != "/usr/local/bin/mihomac" || strings.Join(s.Args, " ") != "mcp" {
		t.Errorf("config = %+v", cfg)
	}
}

func TestSetupInstructionsMentionClients(t *testing.T) {
	text := SetupInstructions("/bin/mihomac")
	for _, want := range []string{"claude mcp add mihomac -- /bin/mihomac mcp", "Cursor", "claude_desktop_config.json"} {
		if !strings.Contains(text, want) {
			t.Errorf("instructions missing %q", want)
		}
	}
}
