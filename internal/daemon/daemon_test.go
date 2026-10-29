package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/nyaaorick/clash-mihomac/internal/health"
	"github.com/nyaaorick/clash-mihomac/internal/rules"
	"github.com/nyaaorick/clash-mihomac/internal/verge"
)

// Tests must not see this machine's real Verge socket.
func init() {
	verge.ServiceSocket = func() string { return filepath.Join(os.TempDir(), "mihomac-daemon-test-no-such.sock") }
}

const testRuntime = `mixed-port: 7897
mode: rule
external-controller: 'CTRL'
secret: s
tun:
  enable: true
  device: utun1024
proxies:
  - {name: hk, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: GLOBAL, type: select, proxies: [hk]}
rules:
  - MATCH,GLOBAL
`

// fakeVerge is a Verge data directory and a fake mihomo controller that
// records what it is asked to load.
type fakeVerge struct {
	dir  verge.Dir
	srv  *httptest.Server
	mu   sync.Mutex
	put  []map[string]any // payloads mihomo was handed
	fail bool             // reject the next PUT /configs
	cur  map[string]any   // what the fake core is running
}

func newFakeVerge(t *testing.T) *fakeVerge {
	t.Helper()
	f := &fakeVerge{dir: verge.Dir(t.TempDir())}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.URL.Path == "/version":
			json.NewEncoder(w).Encode(map[string]string{"version": "test"})
		case r.URL.Path == "/configs" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]any{"mode": f.cur["mode"]})
		case r.URL.Path == "/configs" && r.Method == http.MethodPatch:
			var body struct{ Mode string }
			json.NewDecoder(r.Body).Decode(&body)
			f.cur["mode"] = body.Mode
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/configs" && r.Method == http.MethodPut:
			var body struct{ Payload string }
			json.NewDecoder(r.Body).Decode(&body)
			cfg := map[string]any{}
			if err := yaml.Unmarshal([]byte(body.Payload), &cfg); err != nil || f.fail {
				f.fail = false
				http.Error(w, `{"message":"bad config"}`, http.StatusBadRequest)
				return
			}
			f.put = append(f.put, cfg)
			f.cur = cfg
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/rules":
			var out []ctrlRule
			for i, l := range f.cur["rules"].([]any) {
				parts := strings.Split(l.(string), ",")
				cr := ctrlRule{Index: i, Type: parts[0]}
				if len(parts) >= 3 {
					cr.Payload, cr.Proxy = parts[1], parts[2]
				} else {
					cr.Proxy = parts[1]
				}
				out = append(out, cr)
			}
			json.NewEncoder(w).Encode(map[string]any{"rules": out})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	runtime := strings.Replace(testRuntime, "CTRL", strings.TrimPrefix(f.srv.URL, "http://"), 1)
	os.MkdirAll(f.dir.Path("profiles"), 0o700)
	os.WriteFile(f.dir.Path(verge.RuntimeFile), []byte(runtime), 0o600)
	os.WriteFile(f.dir.Path(verge.ProfilesFile), []byte("items:\n- uid: Merge\n  type: merge\n  file: Merge.yaml\n"), 0o600)
	rt, _ := verge.ParseRuntime([]byte(runtime))
	f.cur = rt.Config
	return f
}

func (f *fakeVerge) daemon(t *testing.T) *Daemon {
	t.Helper()
	home := t.TempDir()
	d := &Daemon{
		o: Options{Home: home, Verge: f.dir}, home: home,
		ctrl:      tcpController(strings.TrimPrefix(f.srv.URL, "http://"), "s"),
		tracker:   NewTracker(),
		proposals: LoadProposals(filepath.Join(home, "proposals.json")),
		health:    health.LoadHistory(filepath.Join(home, "health.json")),
	}
	d.mu.Lock()
	d.refreshRuntime()
	d.recompile()
	d.mihomoVersion = "test"
	d.mu.Unlock()
	return d
}

func TestApplyRulesWritesMergeAndHotLoads(t *testing.T) {
	f := newFakeVerge(t)
	d := f.daemon(t)
	set := rules.Set{Rules: []rules.Rule{{Type: rules.TypeDomainSuffix, Value: "corp.example", Target: "iface:en1"}}}
	if err := d.ApplyRules(context.Background(), set); err != nil {
		t.Fatal(err)
	}

	// The Merge file carries the rules, the bypass, and the interface outbound.
	merge, err := verge.ReadMerge(f.dir.Path("profiles", "Merge.yaml"))
	if err != nil || len(merge.Rules) != 1+len(rules.Bypass) || merge.Rules[0] != "DOMAIN-SUFFIX,corp.example,iface:en1" {
		t.Fatalf("merge = %+v, %v", merge, err)
	}
	if len(merge.Proxies) != 1 || merge.Proxies[0]["interface-name"] != "en1" {
		t.Errorf("merge proxies = %v", merge.Proxies)
	}
	// The running core got the same, in front of the profile's rules.
	if len(f.put) != 1 {
		t.Fatalf("hot loads = %d", len(f.put))
	}
	got := f.put[0]["rules"].([]any)
	if got[0] != "DOMAIN-SUFFIX,corp.example,iface:en1" || got[len(got)-1] != "MATCH,GLOBAL" {
		t.Errorf("core rules = %v", got)
	}
	if f.put[0]["mixed-port"] != 7897 || f.put[0]["secret"] != "s" {
		t.Errorf("hot load must keep Verge's own settings: %v", f.put[0])
	}
	d.mu.Lock()
	active, srcs := d.rulesActive, d.sources
	d.mu.Unlock()
	if !active || srcs[0].Kind != "user" || srcs[len(srcs)-1].Kind != "config" {
		t.Errorf("active=%v sources=%v", active, srcs)
	}
	if saved, _ := rules.Load(filepath.Join(d.home, "rules.yaml")); len(saved.Rules) != 1 {
		t.Errorf("rules.yaml = %+v", saved)
	}

	// Applying again doesn't duplicate anything, even once Verge has
	// folded the Merge file into its runtime config.
	os.WriteFile(f.dir.Path(verge.RuntimeFile), mustYAML(f.cur), 0o600)
	d.mu.Lock()
	d.refreshRuntime()
	d.mu.Unlock()
	if err := d.ReloadConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	got = f.put[1]["rules"].([]any)
	if len(got) != len(f.put[0]["rules"].([]any)) {
		t.Errorf("re-apply duplicated rules: %d vs %d", len(got), len(f.put[0]["rules"].([]any)))
	}
	if px := f.put[1]["proxies"].([]any); len(px) != 2 {
		t.Errorf("re-apply duplicated proxies: %v", px)
	}
	d.mu.Lock()
	warnings := d.warnings
	d.mu.Unlock()
	if len(warnings) != 0 {
		t.Errorf("re-apply must not report its own outbounds as clashes: %v", warnings)
	}
}

func TestApplyRulesRejectsUnknownTargetsBeforeTouchingVerge(t *testing.T) {
	f := newFakeVerge(t)
	d := f.daemon(t)
	set := rules.Set{Rules: []rules.Rule{{Type: rules.TypeDomain, Value: "a.example", Target: "nope"}}}
	err := d.ApplyRules(context.Background(), set)
	if err == nil || !strings.Contains(err.Error(), `"nope"`) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(f.dir.Path("profiles", "Merge.yaml")); err == nil {
		t.Error("merge file written for an invalid set")
	}
	if len(f.put) != 0 {
		t.Error("core touched for an invalid set")
	}
}

func TestRejectedHotLoadRestoresMergeFile(t *testing.T) {
	f := newFakeVerge(t)
	d := f.daemon(t)
	first := rules.Set{Rules: []rules.Rule{{Type: rules.TypeDomain, Value: "a.example", Target: "DIRECT"}}}
	if err := d.ApplyRules(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.fail = true
	f.mu.Unlock()
	second := rules.Set{Rules: []rules.Rule{{Type: rules.TypeDomain, Value: "b.example", Target: "DIRECT"}}}
	if err := d.ApplyRules(context.Background(), second); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("err = %v", err)
	}
	merge, _ := verge.ReadMerge(f.dir.Path("profiles", "Merge.yaml"))
	if merge.Rules[0] != "DOMAIN,a.example,DIRECT" {
		t.Errorf("merge file not restored: %v", merge.Rules)
	}
	if saved, _ := rules.Load(filepath.Join(d.home, "rules.yaml")); saved.Rules[0].Value != "a.example" {
		t.Errorf("rules.yaml not restored: %+v", saved)
	}
}

func TestApplyRulesWithoutCoreKeepsMergeAndWaits(t *testing.T) {
	f := newFakeVerge(t)
	d := f.daemon(t)
	d.mu.Lock()
	d.mihomoVersion = "" // Verge isn't running
	d.mu.Unlock()
	set := rules.Set{Rules: []rules.Rule{{Type: rules.TypeDomain, Value: "a.example", Target: "DIRECT"}}}
	if err := d.ApplyRules(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	if len(f.put) != 0 {
		t.Error("core must not be touched while unreachable")
	}
	if merge, _ := verge.ReadMerge(f.dir.Path("profiles", "Merge.yaml")); len(merge.Rules) == 0 {
		t.Error("merge file not written")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.pendingRestart || d.rulesActive {
		t.Errorf("pending=%v active=%v", d.pendingRestart, d.rulesActive)
	}
}

func TestAlignSourcesDetectsRulesAtFront(t *testing.T) {
	c, _ := rules.Compile(rules.Set{Rules: []rules.Rule{{Type: rules.TypeIPCIDR, Value: "10.1.0.0/16", Target: "DIRECT"}}})
	var ctrl []ctrlRule
	for _, l := range c.Rules {
		p, tgt := splitRuleLine(l)
		ctrl = append(ctrl, ctrlRule{Payload: p, Proxy: tgt})
	}
	ctrl = append(ctrl, ctrlRule{Type: "Match", Proxy: "GLOBAL"})
	active, src := alignSources(ctrl, c)
	if !active || len(src) != len(ctrl) || src[0].Kind != "user" || src[1].Kind != "bypass" || src[len(src)-1] != (rules.Source{Kind: "config", Index: 1}) {
		t.Errorf("active=%v src=%v", active, src)
	}
	// A core without them (a script replaced the rules) labels everything as the profile's.
	active, src = alignSources(ctrl[len(ctrl)-1:], c)
	if active || src[0].Kind != "config" {
		t.Errorf("active=%v src=%v", active, src)
	}
	if p, tgt := splitRuleLine("PROCESS-PATH-REGEX,^/Applications/A, B\\.app/,DIRECT"); p != "^/Applications/A, B\\.app/" || tgt != "DIRECT" {
		t.Errorf("split = %q %q", p, tgt)
	}
}

func mustYAML(v any) []byte {
	out, _ := yaml.Marshal(v)
	return out
}

func TestReconnectRestoresRulesVergeDropped(t *testing.T) {
	f := newFakeVerge(t)
	d := f.daemon(t)
	set := rules.Set{Rules: []rules.Rule{{Type: rules.TypeDomain, Value: "a.example", Target: "DIRECT"}}}
	if err := d.ApplyRules(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	// Verge restarts and a script profile throws the rules away.
	f.mu.Lock()
	rt, _ := verge.ParseRuntime([]byte(strings.Replace(testRuntime, "CTRL", strings.TrimPrefix(f.srv.URL, "http://"), 1)))
	f.cur = rt.Config
	f.put = nil
	f.mu.Unlock()
	d.mu.Lock()
	d.mihomoVersion = ""
	d.mu.Unlock()

	var lastMod time.Time
	d.checkCore(context.Background(), &lastMod)
	deadline := time.Now().Add(3 * time.Second)
	for {
		f.mu.Lock()
		n := len(f.put)
		f.mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.put) != 1 {
		t.Fatalf("hot loads after reconnect = %d, want 1", len(f.put))
	}
	if got := f.put[0]["rules"].([]any); got[0] != "DOMAIN,a.example,DIRECT" {
		t.Errorf("restored rules = %v", got)
	}

	// A user with nothing of their own is left alone.
	d2 := newFakeVerge(t).daemon(t)
	d2.mu.Lock()
	d2.mihomoVersion = ""
	d2.mu.Unlock()
	d2.checkCore(context.Background(), &lastMod)
	time.Sleep(100 * time.Millisecond)
	d2.mu.Lock()
	defer d2.mu.Unlock()
	if d2.pendingRestart || d2.rulesActive {
		t.Errorf("no-config daemon touched the core: pending=%v active=%v", d2.pendingRestart, d2.rulesActive)
	}
}

// Verge applied patch A; the user then edits twice without Verge
// re-applying. The runtime config still carries A, so A must be stripped
// on both edits, not just the first.
func TestLaterEditsStripWhatVergeApplied(t *testing.T) {
	f := newFakeVerge(t)
	d := f.daemon(t)
	rule := func(v string) rules.Set {
		return rules.Set{Rules: []rules.Rule{{Type: rules.TypeDomain, Value: v, Target: "DIRECT"}}}
	}
	if err := d.ApplyRules(context.Background(), rule("a.example")); err != nil {
		t.Fatal(err)
	}
	// Verge rebuilds its config from the Merge file (A inside).
	os.WriteFile(f.dir.Path(verge.RuntimeFile), mustYAML(f.cur), 0o600)
	d.mu.Lock()
	d.refreshRuntime()
	d.mu.Unlock()
	if err := d.ApplyRules(context.Background(), rule("b.example")); err != nil {
		t.Fatal(err)
	}
	if err := d.ApplyRules(context.Background(), rule("c.example")); err != nil {
		t.Fatal(err)
	}
	got := f.put[len(f.put)-1]["rules"].([]any)
	var seen []string
	for _, r := range got {
		if s := r.(string); strings.HasPrefix(s, "DOMAIN,") {
			seen = append(seen, s)
		}
	}
	if len(seen) != 1 || seen[0] != "DOMAIN,c.example,DIRECT" {
		t.Errorf("core rules after the third edit = %v (want only c)", seen)
	}
}

func TestNonConfigHTTPErrorsDoNotRollBack(t *testing.T) {
	f := newFakeVerge(t)
	d := f.daemon(t)
	d.ctrl.set(verge.Endpoint{Network: "tcp", Address: strings.TrimPrefix(f.srv.URL, "http://"), Secret: "stale"})
	set := rules.Set{Rules: []rules.Rule{{Type: rules.TypeDomain, Value: "a.example", Target: "DIRECT"}}}
	if err := d.ApplyRules(context.Background(), set); err != nil {
		t.Fatalf("a 401 must not count as a rejected config: %v", err)
	}
	if merge, _ := verge.ReadMerge(f.dir.Path("profiles", "Merge.yaml")); len(merge.Rules) == 0 {
		t.Error("merge file rolled back on a 401")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.pendingRestart {
		t.Error("pending restart not set")
	}
}

func TestSetModeSurvivesHotLoad(t *testing.T) {
	f := newFakeVerge(t)
	d := f.daemon(t)
	if err := d.SetMode(context.Background(), "sideways"); err == nil {
		t.Error("bad mode accepted")
	}
	if err := d.SetMode(context.Background(), "global"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if f.cur["mode"] != "global" {
		t.Errorf("core mode = %v", f.cur["mode"])
	}
	f.mu.Unlock()
	// The runtime config still says "rule"; a hot-load must not revert the switch.
	set := rules.Set{Rules: []rules.Rule{{Type: rules.TypeDomain, Value: "a.example", Target: "DIRECT"}}}
	if err := d.ApplyRules(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.put[0]["mode"] != "global" {
		t.Errorf("hot-load sent mode %v, want the live global", f.put[0]["mode"])
	}
	// checkCore learns the mode from the core.
	f.cur["mode"] = "direct"
	f.mu.Unlock()
	var lastMod time.Time
	d.checkCore(context.Background(), &lastMod)
	f.mu.Lock()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.liveMode != "direct" {
		t.Errorf("liveMode = %q", d.liveMode)
	}
}
