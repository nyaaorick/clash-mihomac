package verge

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Tests must not see this machine's real service socket.
func init() {
	ServiceSocket = func() string { return filepath.Join(os.TempDir(), "mihomac-test-no-such.sock") }
}

const sampleRuntime = `mixed-port: 7897
mode: global
external-controller: ''
secret: set-your-secret
external-controller-unix: /tmp/verge-mihomo.sock
find-process-mode: always
tun:
  enable: true
  device: utun1024
  stack: gvisor
dns:
  enable: true
  nameserver: [system]
proxies:
  - {name: hk, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: GLOBAL, type: select, proxies: [hk]}
rules:
  - MATCH,GLOBAL
`

func TestParseRuntimePrefersUnixSocket(t *testing.T) {
	r, err := ParseRuntime([]byte(sampleRuntime))
	if err != nil {
		t.Fatal(err)
	}
	if r.MixedPort != 7897 || r.Mode != "global" || !r.TUN || r.TUNDevice != "utun1024" || r.Secret != "set-your-secret" {
		t.Errorf("runtime = %+v", r)
	}
	ep, err := r.Endpoint()
	if err != nil || ep.Network != "unix" || ep.Address != "/tmp/verge-mihomo.sock" || ep.Secret != "set-your-secret" {
		t.Errorf("endpoint = %+v, %v", ep, err)
	}
	p, g := r.Names()
	if len(p) != 1 || p[0] != "hk" || len(g) != 1 || g[0] != "GLOBAL" {
		t.Errorf("names = %v %v", p, g)
	}
}

func TestEndpointPrefersASocketThatExists(t *testing.T) {
	// Unix socket paths are limited to ~100 bytes on macOS, so not t.TempDir().
	dir, err := os.MkdirTemp(os.TempDir(), "mihomac-ep-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	live := filepath.Join(dir, "live.sock")
	ln, err := net.Listen("unix", live)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// The service's socket exists, the configured one doesn't: the service's wins over TCP.
	old := ServiceSocket
	ServiceSocket = func() string { return live }
	defer func() { ServiceSocket = old }()
	r, _ := ParseRuntime([]byte("external-controller: '127.0.0.1:9097'\nexternal-controller-unix: " + filepath.Join(dir, "configured.sock") + "\nsecret: s\n"))
	ep, err := r.Endpoint()
	if err != nil || ep.Network != "unix" || ep.Address != live {
		t.Errorf("endpoint = %+v, %v", ep, err)
	}
	// Neither socket exists: TCP, since Verge has it on.
	ServiceSocket = func() string { return filepath.Join(dir, "none.sock") }
	if ep, _ := r.Endpoint(); ep.Network != "tcp" || ep.Address != "127.0.0.1:9097" {
		t.Errorf("endpoint = %+v", ep)
	}
	// Neither exists and TCP is off: the configured socket, for a Verge that isn't up yet.
	r, _ = ParseRuntime([]byte("external-controller: ''\nexternal-controller-unix: " + filepath.Join(dir, "configured.sock") + "\n"))
	if ep, err := r.Endpoint(); err != nil || ep.Address != filepath.Join(dir, "configured.sock") {
		t.Errorf("endpoint = %+v, %v", ep, err)
	}
}

func TestEndpointFallsBackToTCP(t *testing.T) {
	r, _ := ParseRuntime([]byte("external-controller: ':9097'\nsecret: s\n"))
	ep, err := r.Endpoint()
	if err != nil || ep.Network != "tcp" || ep.Address != "127.0.0.1:9097" {
		t.Errorf("endpoint = %+v, %v", ep, err)
	}
	r, _ = ParseRuntime([]byte("mixed-port: 7897\n"))
	if _, err := r.Endpoint(); err == nil {
		t.Error("no controller should be an error")
	}
}

func TestMergeFileFromIndex(t *testing.T) {
	d := Dir(t.TempDir())
	os.WriteFile(d.Path(ProfilesFile), []byte("items:\n- uid: Merge\n  type: merge\n  file: Custom.yaml\n- uid: x\n  type: local\n  file: x.yaml\n"), 0o600)
	got, err := d.MergeFile()
	if err != nil || got != d.Path("profiles", "Custom.yaml") {
		t.Errorf("merge file = %q, %v", got, err)
	}
	os.WriteFile(d.Path(ProfilesFile), []byte("items: []\n"), 0o600)
	if got, _ := d.MergeFile(); got != d.Path("profiles", "Merge.yaml") {
		t.Errorf("default merge file = %q", got)
	}
}

func TestWriteMergeKeepsOtherKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Merge.yaml")
	os.WriteFile(path, []byte("# user comment\nlog-level: debug\nprepend-rules:\n  - DOMAIN,old.example,DIRECT\n"), 0o600)
	p := Patch{
		Rules:   []string{"DOMAIN-SUFFIX,corp.example,iface:en1"},
		Proxies: []map[string]any{{"name": "iface:en1", "type": "direct", "interface-name": "en1"}},
	}
	if err := WriteMerge(path, p); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), "# Written by Clash Mihomac") {
		t.Errorf("missing header:\n%s", data)
	}
	doc := map[string]any{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["log-level"] != "debug" {
		t.Errorf("foreign key lost: %v", doc)
	}
	rules, _ := doc["prepend-rules"].([]any)
	if len(rules) != 1 || rules[0] != "DOMAIN-SUFFIX,corp.example,iface:en1" {
		t.Errorf("prepend-rules = %v", doc["prepend-rules"])
	}
	if _, ok := doc["append-proxy-groups"]; ok {
		t.Error("empty groups must not be written")
	}

	// Clearing the patch removes the managed keys and keeps the rest.
	if err := WriteMerge(path, Patch{}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	doc = map[string]any{}
	yaml.Unmarshal(data, &doc)
	if _, ok := doc["prepend-rules"]; ok || doc["log-level"] != "debug" {
		t.Errorf("after clearing: %v", doc)
	}
}

func TestApplyPatchesLikeVerge(t *testing.T) {
	r, _ := ParseRuntime([]byte(sampleRuntime))
	out, skipped := Apply(r.Config, Patch{
		Rules:            []string{"DOMAIN,a.example,DIRECT"},
		Proxies:          []map[string]any{{"name": "hk", "type": "ss"}, {"name": "jp", "type": "ss"}},
		Groups:           []map[string]any{{"name": "auto", "type": "fallback", "proxies": []any{"jp"}}},
		NameserverPolicy: map[string]any{"+.corp.example": []string{"dhcp://en1"}},
	})
	if len(skipped) != 1 || skipped[0] != "hk" {
		t.Errorf("skipped = %v", skipped)
	}
	rules, _ := out["rules"].([]any)
	if len(rules) != 2 || rules[0] != "DOMAIN,a.example,DIRECT" || rules[1] != "MATCH,GLOBAL" {
		t.Errorf("rules = %v", rules)
	}
	proxies, _ := out["proxies"].([]any)
	if len(proxies) != 2 || proxies[1].(map[string]any)["name"] != "jp" {
		t.Errorf("proxies = %v", proxies)
	}
	groups, _ := out["proxy-groups"].([]any)
	if len(groups) != 2 {
		t.Errorf("groups = %v", groups)
	}
	dns, _ := out["dns"].(map[string]any)
	policy, _ := dns["nameserver-policy"].(map[string]any)
	if dns["enable"] != true || policy["+.corp.example"] == nil {
		t.Errorf("dns = %v", dns)
	}
	// The input is untouched.
	if n, _ := r.Config["rules"].([]any); len(n) != 1 {
		t.Error("Apply must not modify its input")
	}
	if _, err := yaml.Marshal(out); err != nil {
		t.Errorf("result must serialize: %v", err)
	}
}

func TestAddWebUI(t *testing.T) {
	d := Dir(t.TempDir())
	os.WriteFile(d.Path(SettingsFile), []byte("enable_tun_mode: true\nweb_ui_list:\n  - https://yacd.example/?hostname=%host\n"), 0o600)
	changed, err := d.AddWebUI("http://127.0.0.1:9991/?token=abc")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	changed, err = d.AddWebUI("http://127.0.0.1:9991/?token=abc")
	if err != nil || changed {
		t.Errorf("second add: changed=%v err=%v", changed, err)
	}
	s, err := d.ReadSettings()
	if err != nil || !s.TUNMode || len(s.WebUIList) != 2 || s.WebUIList[1] != "http://127.0.0.1:9991/?token=abc" {
		t.Errorf("settings = %+v, %v", s, err)
	}
}

type fakeRunner struct {
	calls   []string
	running int // how many pgrep calls still report the app
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if strings.HasSuffix(name, "pgrep") {
		if f.running > 0 {
			f.running--
			return "123\n", nil
		}
		return "", context.DeadlineExceeded // pgrep exits 1 when nothing matches
	}
	return "", nil
}

func TestRestartQuitsWaitsAndRelaunches(t *testing.T) {
	r := &fakeRunner{running: 3}
	if err := Restart(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	quit := strings.Index(joined, "osascript")
	open := strings.Index(joined, "/usr/bin/open -a Clash Verge")
	if quit < 0 || open < 0 || quit > open {
		t.Errorf("calls:\n%s", joined)
	}
	if !strings.Contains(joined, `tell application "Clash Verge" to quit`) {
		t.Errorf("quit script wrong:\n%s", joined)
	}

	// Not running: just launch.
	r = &fakeRunner{}
	if err := Restart(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(r.calls, "\n"), "osascript") {
		t.Errorf("should not quit an app that isn't running: %v", r.calls)
	}
}

func TestReadMergeAndStripRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Merge.yaml")
	p := Patch{
		Rules:   []string{"DOMAIN,a.example,DIRECT"},
		Proxies: []map[string]any{{"name": "jp", "type": "ss"}},
		Groups:  []map[string]any{{"name": "auto", "type": "fallback", "proxies": []any{"jp"}}},
	}
	if err := WriteMerge(path, p); err != nil {
		t.Fatal(err)
	}
	prev, err := ReadMerge(path)
	if err != nil || len(prev.Rules) != 1 || len(prev.Proxies) != 1 || len(prev.Groups) != 1 {
		t.Fatalf("read back %+v, %v", prev, err)
	}
	if prev, err := ReadMerge(filepath.Join(t.TempDir(), "none.yaml")); err != nil || len(prev.Rules) != 0 {
		t.Errorf("missing file: %+v, %v", prev, err)
	}

	// A runtime config that already carries the patch (Verge applied it)
	// comes back to the profile's own content after Strip.
	r, _ := ParseRuntime([]byte(sampleRuntime))
	applied, _ := Apply(r.Config, p)
	stripped := Strip(applied, prev)
	if rules, _ := stripped["rules"].([]any); len(rules) != 1 || rules[0] != "MATCH,GLOBAL" {
		t.Errorf("rules after strip = %v", stripped["rules"])
	}
	if proxies, _ := stripped["proxies"].([]any); len(proxies) != 1 {
		t.Errorf("proxies after strip = %v", stripped["proxies"])
	}
	if groups, _ := stripped["proxy-groups"].([]any); len(groups) != 1 {
		t.Errorf("groups after strip = %v", stripped["proxy-groups"])
	}
	// Applying again after stripping doesn't duplicate anything.
	again, skipped := Apply(stripped, p)
	if len(skipped) != 0 {
		t.Errorf("skipped = %v", skipped)
	}
	if rules, _ := again["rules"].([]any); len(rules) != 2 {
		t.Errorf("rules after re-apply = %v", rules)
	}
}

func TestApplySkipsDuplicateGroupsAndStripKeepsLookalikes(t *testing.T) {
	r, _ := ParseRuntime([]byte(sampleRuntime))
	// A group named like one the profile has is skipped, not duplicated.
	out, skipped := Apply(r.Config, Patch{Groups: []map[string]any{{"name": "GLOBAL", "type": "fallback", "proxies": []any{"hk"}}}})
	if len(skipped) != 1 || skipped[0] != "GLOBAL" {
		t.Errorf("skipped = %v", skipped)
	}
	if groups, _ := out["proxy-groups"].([]any); len(groups) != 1 {
		t.Errorf("groups = %v", groups)
	}
	// Strip removes only entries equal to the earlier patch, not the
	// profile's own proxy that happens to share the name.
	prev := Patch{Proxies: []map[string]any{{"name": "hk", "type": "ss", "server": "198.51.100.9", "port": 1}}}
	stripped := Strip(r.Config, prev)
	if proxies, _ := stripped["proxies"].([]any); len(proxies) != 1 {
		t.Errorf("profile proxy removed: %v", proxies)
	}
	applied, _ := Apply(r.Config, prev)
	if proxies, _ := Strip(applied, Patch{Proxies: []map[string]any{{"name": "hk", "type": "ss", "server": "198.51.100.9", "port": 1}}})["proxies"].([]any); len(proxies) != 1 {
		t.Errorf("own proxy not removed: %v", proxies)
	}
	// Stripping everything leaves empty lists, not null.
	emptied := Strip(map[string]any{"rules": []any{"MATCH,DIRECT"}}, Patch{Rules: []string{"MATCH,DIRECT"}})
	if rules, ok := emptied["rules"].([]any); !ok || rules == nil || len(rules) != 0 {
		t.Errorf("rules = %#v", emptied["rules"])
	}
}
