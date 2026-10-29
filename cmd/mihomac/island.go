package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/buildinfo"
	"github.com/nyaaorick/clash-mihomac/internal/client"
	"github.com/nyaaorick/clash-mihomac/internal/daemon"
	"github.com/nyaaorick/clash-mihomac/internal/paths"
	"github.com/nyaaorick/clash-mihomac/internal/verge"
)

// cmdIsland runs Clash Mihomac as an island4mac plugin: the daemon (GUI, API,
// MCP server and all) runs in this process, and the island's tab shows what
// it knows over the plugin protocol (JSON lines on stdin and stdout). The
// data directory is the one the island hands us (ISLAND_DATA_DIR), so an
// update of the plugin never touches rules, nodes or history. Documented in
// island4mac's spec/docs/04-plugin-protocol.md.
func cmdIsland(args []string) error {
	home, err := islandHome()
	if err != nil {
		return err
	}
	// Everything else in this program resolves the data directory through
	// paths.Home(), which honours MIHOMAC_HOME.
	os.Setenv("MIHOMAC_HOME", home)
	logger := log.New(os.Stderr, "", log.LstdFlags)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// The island closes our stdin when it wants us gone.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p := &islandPlugin{home: home, out: bufio.NewWriter(os.Stdout), logger: logger, events: make(chan islandEvent, 16)}
	go p.readEvents(ctx, os.Stdin, cancel)
	daemonDone := make(chan struct{})
	go func() {
		defer close(daemonDone)
		p.runDaemon(ctx)
	}()
	p.loop(ctx)
	// Let the daemon close its listener and remove its state file before we go
	cancel()
	select {
	case <-daemonDone:
	case <-time.After(5 * time.Second):
	}
	return nil
}

// islandHome is the data directory for the island run: ISLAND_DATA_DIR, with
// what an earlier standalone install kept moved in the first time.
func islandHome() (string, error) {
	dir := os.Getenv("ISLAND_DATA_DIR")
	if dir == "" {
		return paths.Home()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(dir, "gui-token")); err == nil {
		return dir, nil
	}
	old, err := paths.Home()
	if err != nil || old == dir {
		return dir, nil
	}
	entries, err := os.ReadDir(old)
	if err != nil {
		return dir, nil
	}
	for _, e := range entries {
		if e.Name() == daemon.StateFile || strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		dest := filepath.Join(dir, e.Name())
		if _, err := os.Stat(dest); err == nil {
			continue
		}
		os.Rename(filepath.Join(old, e.Name()), dest)
	}
	return dir, nil
}

// islandEvent is one line from the island.
type islandEvent struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Tab  bool   `json:"tab"`
}

type islandPlugin struct {
	home   string
	out    *bufio.Writer
	logger *log.Logger
	events chan islandEvent

	mu        sync.Mutex
	daemonErr string // why the daemon isn't running, if it isn't
	vergeDir  verge.Dir
	api       *client.Client

	lastSent map[string]string
	visible  bool
}

func (p *islandPlugin) readEvents(ctx context.Context, r io.Reader, closed func()) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		var ev islandEvent
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		select {
		case p.events <- ev:
		case <-ctx.Done():
			return
		}
	}
	closed()
}

// runDaemon keeps the daemon running in this process, retrying when Clash
// Verge's data directory isn't there yet or the GUI port is taken by a
// standalone `mihomac start`.
func (p *islandPlugin) runDaemon(ctx context.Context) {
	for ctx.Err() == nil {
		vd, err := verge.Locate()
		if err != nil {
			p.setDaemonErr("Clash Verge isn't installed: " + err.Error())
			sleepCtx(ctx, 10*time.Second)
			continue
		}
		p.mu.Lock()
		p.vergeDir = vd
		p.daemonErr = ""
		p.api = nil
		p.mu.Unlock()
		err = daemon.Run(ctx, daemon.Options{
			Home: p.home, Verge: vd, GUIPort: paths.GUIPort(), Channel: buildinfo.Channel, Log: p.logger,
		})
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "address already in use") {
				msg = fmt.Sprintf("another Clash Mihomac holds port %d; stop it with `mihomac stop`", paths.GUIPort())
			}
			p.setDaemonErr(msg)
		}
		sleepCtx(ctx, 10*time.Second)
	}
}

func (p *islandPlugin) setDaemonErr(msg string) {
	p.mu.Lock()
	p.daemonErr = msg
	p.api = nil
	p.mu.Unlock()
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// connect returns the API client once the daemon has written its state.
func (p *islandPlugin) connect() *client.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.api != nil {
		return p.api
	}
	if p.daemonErr != "" {
		return nil
	}
	c, err := client.Connect(p.home, client.TokenFull)
	if err != nil {
		return nil
	}
	c.HTTP.Timeout = 10 * time.Second
	p.api = c
	return c
}

// loop polls the daemon and shows what changed; taps come in on events.
func (p *islandPlugin) loop(ctx context.Context) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var view islandView
	nodesAt := time.Time{}
	refresh := func() {
		view.DaemonErr, view.Status = "", nil
		p.mu.Lock()
		view.DaemonErr = p.daemonErr
		p.mu.Unlock()
		if api := p.connect(); api != nil {
			var st daemon.Status
			if err := api.Get(ctx, "/api/status", &st); err == nil {
				view.Status = &st
			} else {
				view.DaemonErr = "the daemon isn't answering: " + err.Error()
			}
			// Nodes change slowly and the call is heavier; while the tab is open
			// they refresh every poll so a delay test shows at once.
			if view.Status != nil && (p.visible || time.Since(nodesAt) > 10*time.Second) {
				var nodes []daemon.Node
				if err := api.Get(ctx, "/api/nodes", &nodes); err == nil {
					view.Nodes = nodes
					nodesAt = time.Now()
				}
			}
		}
		p.show(renderIsland(view))
	}
	refresh()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			refresh()
		case ev := <-p.events:
			switch ev.Type {
			case "visible":
				p.visible = ev.Tab
			case "action":
				p.act(ctx, ev.ID, view)
				refresh()
			}
		}
	}
}

// act carries out a tap.
func (p *islandPlugin) act(ctx context.Context, id string, view islandView) {
	api := p.connect()
	actx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var err error
	switch {
	case strings.HasPrefix(id, "mode:") && api != nil:
		var st daemon.Status
		err = api.Post(actx, "/api/verge/mode", map[string]string{"mode": strings.TrimPrefix(id, "mode:")}, &st)
	case id == "apply" && api != nil:
		var st daemon.Status
		err = api.Post(actx, "/api/verge/apply", nil, &st)
	case id == "check" && api != nil:
		var hv daemon.HealthView
		err = api.Post(actx, "/api/health/check", nil, &hv)
	case id == "restart" && api != nil:
		var st daemon.Status
		err = api.Post(actx, "/api/verge/restart", nil, &st)
	case id == "dashboard":
		if view.Status != nil && view.Status.WebUIURL != "" {
			err = exec.CommandContext(actx, "/usr/bin/open", view.Status.WebUIURL).Run()
		}
	case id == "open-verge":
		var app verge.App
		if app, err = verge.FindApp(actx, execRunner{}); err == nil {
			err = app.Open(actx, execRunner{})
		}
	case id == "install":
		p.popup("Installing Clash Verge…", "arrow.down.circle", 5)
		_, err = installVerge(actx, execRunner{}, "/Applications", false)
		if err == nil {
			p.popup("Clash Verge installed", "checkmark.circle", 3)
		}
	default:
		return
	}
	if err != nil {
		p.logger.Printf("island: %s: %v", id, err)
		p.popup(firstLine(err.Error()), "exclamationmark.triangle", 4)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ---- Rendering ----

// islandView is everything the tab is drawn from.
type islandView struct {
	DaemonErr string
	Status    *daemon.Status
	Nodes     []daemon.Node
}

// Wire types, as island4mac reads them (protocol 7).
type wireCompact struct {
	Type   string `json:"type"`
	Symbol string `json:"symbol,omitempty"`
	Text   string `json:"text,omitempty"`
	State  string `json:"state,omitempty"`
}

type wireRow struct {
	ID       string `json:"id,omitempty"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
	State    string `json:"state,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Toggle   *bool  `json:"toggle,omitempty"`
}

type wireButton struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Symbol  string `json:"symbol,omitempty"`
	Confirm string `json:"confirm,omitempty"`
}

type wirePopup struct {
	Type    string  `json:"type"`
	Symbol  string  `json:"symbol,omitempty"`
	Text    string  `json:"text"`
	Seconds float64 `json:"seconds,omitempty"`
}

// islandContent is what one render shows: nil compact means nothing beside the notch.
type islandContent struct {
	Compact *wireCompact
	Rows    []wireRow
	Buttons []wireButton
}

const maxNodeRows = 24

func section(title, detail string) wireRow {
	return wireRow{Title: title, Detail: detail, Kind: "section"}
}

func boolp(b bool) *bool { return &b }

// renderIsland turns what the daemon says into the tab. Pure, so it is tested.
func renderIsland(v islandView) islandContent {
	c := islandContent{Rows: []wireRow{}, Buttons: []wireButton{}}
	if v.Status == nil {
		msg := v.DaemonErr
		if msg == "" {
			msg = "starting"
		}
		c.Compact = &wireCompact{Type: "compact", Symbol: "network.slash", Text: "Off", State: "failed"}
		if strings.Contains(msg, "isn't installed") {
			c.Rows = append(c.Rows, wireRow{Title: "Clash Verge isn't installed", Subtitle: "Clash Mihomac works alongside Clash Verge Rev, which runs the proxy core", Symbol: "app.dashed", State: "attention"})
			c.Buttons = append(c.Buttons, wireButton{ID: "install", Title: "Install Clash Verge", Symbol: "arrow.down.circle", Confirm: "Download the latest Clash Verge Rev from GitHub and install it in /Applications?"})
		} else {
			c.Rows = append(c.Rows, wireRow{Title: "Clash Mihomac isn't running", Subtitle: msg, Symbol: "network.slash", State: "failed"})
		}
		return c
	}
	st := v.Status
	vg := st.Verge
	connected := vg.MihomoVersion != ""
	mode := strings.ToUpper(vg.Mode[:min(1, len(vg.Mode))]) + vg.Mode[min(1, len(vg.Mode)):]

	// Beside the notch: the mode, and whether anything needs the user
	compact := &wireCompact{Type: "compact", Symbol: "network", Text: mode}
	switch {
	case !connected:
		compact.Symbol, compact.Text, compact.State = "network.slash", "Off", "failed"
	case st.PendingRestart || (st.HasRules && !st.RulesActive):
		compact.State = "attention"
	}
	if vg.TUN && connected {
		compact.Text += " · TUN"
	}
	c.Compact = compact

	// Clash Verge
	c.Rows = append(c.Rows, section("Clash Verge", vg.MihomoVersion))
	if connected {
		c.Rows = append(c.Rows, wireRow{Title: "Core", Subtitle: "mihomo " + vg.MihomoVersion + " via " + vg.Controller, Symbol: "cpu", State: "done",
			Detail: map[bool]string{true: "TUN " + vg.TUNDevice, false: "proxy :" + fmt.Sprint(vg.MixedPort)}[vg.TUN]})
	} else {
		sub := "Clash Verge isn't running"
		if vg.AppRunning {
			sub = "Clash Verge runs, but its core doesn't answer yet"
		}
		if vg.ConfigError != "" {
			sub = vg.ConfigError
		}
		c.Rows = append(c.Rows, wireRow{ID: "open-verge", Title: "Core", Subtitle: sub + " · tap to open Clash Verge", Symbol: "cpu", State: "failed"})
	}
	for _, m := range daemon.Modes {
		title := map[string]string{"rule": "Rule mode", "global": "Global", "direct": "Direct"}[m]
		sub := map[string]string{"rule": "Your rules decide", "global": "Everything through the selected node", "direct": "Nothing through the proxy"}[m]
		c.Rows = append(c.Rows, wireRow{ID: "mode:" + m, Title: title, Subtitle: sub, Symbol: "arrow.triangle.branch", Toggle: boolp(vg.Mode == m)})
	}
	rules := wireRow{Title: "Rules", Symbol: "list.bullet.rectangle", Detail: ruleCounts(st.Rules)}
	switch {
	case st.PendingRestart:
		rules.ID, rules.State, rules.Subtitle = "restart", "attention", "The Merge file changed; restart Clash Verge to apply it"
	case st.HasRules && !st.RulesActive && connected:
		rules.ID, rules.State, rules.Subtitle = "apply", "attention", "Not loaded into the core; tap to load them"
	case st.HasRules && st.RulesActive:
		rules.State, rules.Subtitle = "done", "Loaded ahead of the profile's own"
	default:
		rules.Subtitle = "None yet; add them in the dashboard"
	}
	c.Rows = append(c.Rows, rules)
	if vg.Mode != "rule" && st.HasRules && connected {
		c.Rows = append(c.Rows, wireRow{ID: "mode:rule", Title: "Rules route nothing in " + mode + " mode", Subtitle: "Tap to switch back to rule mode", Symbol: "exclamationmark.triangle", State: "attention"})
	}

	// Nodes: groups first, then the proxies
	if len(v.Nodes) > 0 {
		groups, proxies := splitNodes(v.Nodes)
		c.Rows = append(c.Rows, section("Nodes", fmt.Sprintf("%d", len(proxies))))
		n := 0
		for _, g := range groups {
			if n >= maxNodeRows {
				break
			}
			c.Rows = append(c.Rows, wireRow{Title: g.Name, Subtitle: g.Type + " → " + orDash(g.Now), Symbol: "square.stack.3d.up", Detail: delay(g)})
			n++
		}
		for _, x := range proxies {
			if n >= maxNodeRows {
				c.Rows = append(c.Rows, wireRow{Title: fmt.Sprintf("%d more in the dashboard", len(proxies)-(n-len(groups))), Symbol: "ellipsis"})
				break
			}
			row := wireRow{Title: x.Name, Subtitle: x.Type, Symbol: "point.3.connected.trianglepath.dotted", Detail: delay(x)}
			switch x.Health {
			case "blocked":
				row.State, row.Subtitle = "failed", x.Type+" · looks blocked"
			case "down":
				row.State, row.Subtitle = "failed", x.Type+" · down"
			case "degraded":
				row.State, row.Subtitle = "attention", x.Type+" · recent failures"
			case "healthy":
				row.State = "done"
			default:
				if !x.Alive && x.DelayMs == 0 {
					row.Subtitle = x.Type + " · not checked yet"
				}
			}
			c.Rows = append(c.Rows, row)
			n++
		}
	}

	if len(st.Warnings) > 0 {
		c.Rows = append(c.Rows, section("Warnings", fmt.Sprint(len(st.Warnings))))
		for _, w := range st.Warnings[:min(5, len(st.Warnings))] {
			c.Rows = append(c.Rows, wireRow{Title: firstLine(w), Symbol: "exclamationmark.triangle", State: "attention"})
		}
	}

	c.Buttons = append(c.Buttons, wireButton{ID: "dashboard", Title: "Dashboard", Symbol: "safari"})
	if connected {
		c.Buttons = append(c.Buttons, wireButton{ID: "check", Title: "Check Nodes", Symbol: "waveform.path.ecg"})
		c.Buttons = append(c.Buttons, wireButton{ID: "restart", Title: "Restart Verge", Symbol: "arrow.clockwise", Confirm: "Quit Clash Verge and start it again? Connections drop for a few seconds."})
	}
	return c
}

func ruleCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
	}
	return strings.Join(parts, ", ")
}

func splitNodes(nodes []daemon.Node) (groups, proxies []daemon.Node) {
	for _, n := range nodes {
		switch strings.ToLower(n.Type) {
		case "selector", "urltest", "url-test", "fallback", "loadbalance", "load-balance", "relay":
			groups = append(groups, n)
		case "direct", "reject", "compatible", "pass", "reject-drop":
			// Built-in outbounds say nothing about the network
		default:
			proxies = append(proxies, n)
		}
	}
	return groups, proxies
}

func delay(n daemon.Node) string {
	if n.DelayMs > 0 {
		return fmt.Sprintf("%d ms", n.DelayMs)
	}
	return ""
}

// ---- Writing ----

// show sends what changed since the last render, one line per kind.
func (p *islandPlugin) show(c islandContent) {
	if p.lastSent == nil {
		p.lastSent = map[string]string{}
	}
	send := func(kind string, v any, clear string) {
		if v == nil {
			if _, was := p.lastSent[kind]; was {
				delete(p.lastSent, kind)
				p.write(clear)
			}
			return
		}
		data, err := json.Marshal(v)
		if err != nil {
			return
		}
		line := string(data)
		if p.lastSent[kind] == line {
			return
		}
		p.lastSent[kind] = line
		p.write(line)
	}
	var compact any
	if c.Compact != nil {
		compact = c.Compact
	}
	send("compact", compact, `{"type":"clear","target":"compact"}`)
	send("list", map[string]any{"type": "list", "rows": c.Rows}, `{"type":"clear","target":"list"}`)
	send("buttons", map[string]any{"type": "buttons", "buttons": c.Buttons}, `{"type":"clear","target":"buttons"}`)
}

func (p *islandPlugin) popup(text, symbol string, seconds float64) {
	data, _ := json.Marshal(wirePopup{Type: "popup", Symbol: symbol, Text: text, Seconds: seconds})
	p.write(string(data))
}

func (p *islandPlugin) write(line string) {
	p.out.WriteString(line)
	p.out.WriteByte('\n')
	if err := p.out.Flush(); err != nil && !errors.Is(err, syscall.EPIPE) {
		p.logger.Printf("island: write: %v", err)
	}
}
