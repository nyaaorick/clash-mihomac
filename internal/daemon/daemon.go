// Package daemon runs Clash Mihomac as a companion to Clash Verge Rev. It
// doesn't start a proxy core of its own: Clash Verge owns mihomo, TUN, and
// the system proxy. The daemon finds Verge's mihomo through the files
// Verge writes, watches its connections for diagnostics and the traffic
// view, checks node health, manages servers over SSH, and serves the
// localhost GUI, API, and MCP server.
//
// Rules the user adds here reach mihomo two ways at once: they are written
// into Clash Verge's global Merge profile, which Verge folds into every
// config it generates, and they are hot-loaded into the running core so
// they take effect without a restart. Verge is never told to re-apply (it
// has no way to be told); the Merge file simply takes over the next time
// Verge rebuilds its config.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/nyaaorick/clash-mihomac/internal/gui"
	"github.com/nyaaorick/clash-mihomac/internal/health"
	"github.com/nyaaorick/clash-mihomac/internal/netstate"
	"github.com/nyaaorick/clash-mihomac/internal/rules"
	"github.com/nyaaorick/clash-mihomac/internal/verge"
	"github.com/nyaaorick/clash-mihomac/internal/vps"
)

// Options configure a daemon run.
type Options struct {
	Home    string    // Clash Mihomac's data directory
	Verge   verge.Dir // Clash Verge Rev's data directory
	GUIPort int
	Channel string
	Runner  netstate.Runner // for restarting Verge; nil runs real commands
	Log     *log.Logger
}

// Daemon is the running companion.
type Daemon struct {
	o         Options
	home      string
	ctrl      *controller
	tracker   *Tracker
	proposals *Proposals
	health    *health.History
	traffic   *trafficState
	vps       *vpsState
	startedAt time.Time
	fullToken string

	wg      sync.WaitGroup // background loops; Run waits for them
	applyMu sync.Mutex     // serializes rule applies; never held with d.mu across I/O

	mu             sync.Mutex // guards everything below
	runtime        verge.Runtime
	runtimeErr     string
	strip          verge.Patch // what the runtime config carries of this daemon's earlier patch
	mihomoVersion  string      // empty while mihomo is unreachable
	liveMode       string      // the core's running mode, which may differ from the runtime config's
	ruleSet        rules.Set
	compiled       rules.Compiled
	ctrlRules      []ctrlRule
	sources        []rules.Source // provenance per entry of ctrlRules
	rulesActive    bool           // the running core has this daemon's rules at the front
	pendingRestart bool           // the Merge file changed but the core couldn't be hot-loaded
	warnings       []string
	events         []Event
	appRunning     bool
	app            *verge.App
	webUI          bool
	appChecked     time.Time

	ifaceMu   sync.Mutex
	defIface  string
	ifaceTime time.Time
}

// Event is something the daemon did, shown in the GUI.
type Event struct {
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

// Run starts the companion and blocks until ctx is cancelled. Clash Verge
// not running is not an error: the daemon waits for it.
func Run(ctx context.Context, o Options) error {
	if o.Runner == nil {
		o.Runner = netstate.ExecRunner{}
	}
	if o.Log == nil {
		o.Log = log.New(os.Stderr, "", log.LstdFlags)
	}
	if err := os.MkdirAll(o.Home, 0o700); err != nil {
		return err
	}
	d := newDaemon(o)
	set, err := rules.Load(d.path("rules.yaml"))
	if err != nil {
		return err
	}
	d.ruleSet = set

	// Claim the GUI port first so a port clash fails before anything changes.
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", o.GUIPort))
	if err != nil {
		return fmt.Errorf("GUI port: %w", err)
	}
	defer ln.Close()
	full, err := gui.LoadOrCreateToken(d.path("gui-token"))
	if err != nil {
		return err
	}
	agent, err := gui.LoadOrCreateToken(d.path("mcp-token"))
	if err != nil {
		return err
	}
	d.fullToken = full

	d.mu.Lock()
	d.refreshRuntime()
	d.recompile()
	if d.runtimeErr != "" {
		d.event("Clash Verge: %s", d.runtimeErr)
	}
	d.mu.Unlock()

	d.startedAt = time.Now()
	srv := &http.Server{
		Handler:           gui.Handler(ln.Addr().String(), gui.Tokens{Full: full, Agent: agent}, d.api()),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go srv.Serve(ln)
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()

	if err := writeState(d.home, State{
		PID: os.Getpid(), GUIURL: fmt.Sprintf("http://127.0.0.1:%d/", o.GUIPort),
		VergeDir: string(o.Verge), StartedAt: d.startedAt,
	}); err != nil {
		return err
	}
	defer removeState(d.home)

	d.spawn(func() { d.pollConnections(ctx) })
	d.spawn(func() { d.followLogs(ctx) })
	d.spawn(func() { d.monitorHealth(ctx) })
	d.spawn(func() { d.pollTraffic(ctx) })
	d.spawn(func() { d.monitorMachines(ctx) })
	d.watchCore(ctx)
	d.logf("shutting down")
	d.wg.Wait()
	return nil
}

// spawn runs f in a goroutine that Run waits for.
func (d *Daemon) spawn(f func()) {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		f()
	}()
}

func newDaemon(o Options) *Daemon {
	d := &Daemon{
		o: o, home: o.Home,
		ctrl:      &controller{},
		tracker:   NewTracker(),
		proposals: LoadProposals(filepath.Join(o.Home, "proposals.json")),
		health:    health.LoadHistory(filepath.Join(o.Home, "health.json")),
	}
	d.initTraffic()
	d.initVPS()
	return d
}

// path joins elem onto the data directory.
func (d *Daemon) path(elem ...string) string {
	return filepath.Join(append([]string{d.home}, elem...)...)
}

func (d *Daemon) runner() netstate.Runner {
	if d.o.Runner != nil {
		return d.o.Runner
	}
	return netstate.ExecRunner{}
}

// watchCore keeps the controller pointed at Verge's mihomo. Verge rewrites
// its runtime config on every apply, possibly with a new socket path or
// secret, so the file is re-read whenever it changes, and the core is
// pinged every couple of seconds so the GUI can say whether it is there.
func (d *Daemon) watchCore(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	var lastMod time.Time
	for {
		d.checkCore(ctx, &lastMod)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (d *Daemon) checkCore(ctx context.Context, lastMod *time.Time) {
	changed := false
	if info, err := os.Stat(d.o.Verge.Path(verge.RuntimeFile)); err == nil && !info.ModTime().Equal(*lastMod) {
		*lastMod = info.ModTime()
		changed = true
		d.mu.Lock()
		d.refreshRuntime()
		d.mu.Unlock()
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	v, err := d.ctrl.version(cctx)
	cancel()

	d.mu.Lock()
	defer d.mu.Unlock()
	was := d.mihomoVersion
	if err != nil {
		if was != "" {
			d.event("mihomo is no longer reachable (%v); waiting for Clash Verge", err)
		}
		d.mihomoVersion = ""
		// The socket may have appeared since (Verge's service creates it
		// after the app writes its config), so pick the endpoint again.
		d.refreshRuntime()
		return
	}
	d.mihomoVersion = v
	if was == "" {
		d.event("connected to mihomo %s via %s", v, d.ctrl.endpoint())
	}
	mctx, mcancel := context.WithTimeout(ctx, 2*time.Second)
	if m, err := d.ctrl.mode(mctx); err == nil && m != "" {
		d.liveMode = m
	}
	mcancel()
	if was == "" || changed {
		d.refreshRules(ctx)
	}
	// Verge rebuilt its config (a restart, a profile switch) and the user's
	// rules aren't in it: a Script profile that assigns config.rules drops
	// the Merge file's rules. The user asked for these rules once; put
	// them back without making them click.
	if (was == "" || changed) && !d.rulesActive && d.hasUserConfig() {
		d.spawn(func() {
			if err := d.ReloadConfig(ctx); err != nil {
				d.mu.Lock()
				d.event("couldn't restore the rules after Clash Verge rebuilt its config: %v", err)
				d.mu.Unlock()
			}
		})
	}
}

// Modes the core can run in.
var Modes = []string{"rule", "global", "direct"}

// SetMode switches the running core's mode. This is the same switch as
// in Verge's own window and takes effect at once, but Verge keeps the
// mode in its own settings: the next time it rebuilds its config (a
// restart, a profile switch) the mode comes back from there.
func (d *Daemon) SetMode(ctx context.Context, mode string) error {
	if !slices.Contains(Modes, mode) {
		return fmt.Errorf("unknown mode %q (want rule, global, or direct)", mode)
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := d.ctrl.setMode(cctx, mode); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.liveMode = mode
	d.event("mode switched to %s in the running core", mode)
	return nil
}

// hasUserConfig reports whether the user has anything of their own to
// apply: rules, packs, groups, or imported nodes. Without any, nothing is
// ever pushed into Verge's core unasked. The caller holds d.mu.
func (d *Daemon) hasUserConfig() bool {
	if len(d.ruleSet.Rules) > 0 || len(d.ruleSet.Packs) > 0 || len(d.ruleSet.Groups) > 0 {
		return true
	}
	nodes, _ := vps.LoadNodes(d.path("nodes.yaml"))
	return len(nodes) > 0
}

// refreshRuntime re-reads Verge's runtime config and repoints the
// controller. The caller holds d.mu.
func (d *Daemon) refreshRuntime() {
	rt, err := d.o.Verge.ReadRuntime()
	if err != nil {
		d.runtimeErr = err.Error()
		return
	}
	d.runtime = rt
	// What Verge folded into this config is the Merge file as it stands
	// now (Verge rebuilt the config just before this read), so that is what
	// has to be taken back out before this daemon's patch goes on top.
	d.strip = verge.Patch{}
	if mergePath, err := d.o.Verge.MergeFile(); err == nil {
		if prev, err := verge.ReadMerge(mergePath); err == nil {
			d.strip = prev
		}
	}
	ep, err := rt.Endpoint()
	if err != nil {
		d.runtimeErr = err.Error()
		return
	}
	d.runtimeErr = ""
	d.ctrl.set(ep)
}

// recompile refreshes the compiled form of the rule set. The caller holds d.mu.
func (d *Daemon) recompile() {
	c, err := rules.Compile(d.ruleSet)
	if err != nil {
		d.warnings = append(d.warnings, "rules.yaml: "+err.Error())
		return
	}
	d.compiled = c
}

// vergeState reports whether the Clash Verge app is up, which copy is
// installed, and whether the GUI is in Verge's Web UI list, cached
// briefly because the GUI asks every couple of seconds.
func (d *Daemon) vergeState(ctx context.Context) (running bool, app *verge.App, webUI bool) {
	d.mu.Lock()
	fresh := time.Since(d.appChecked) < 5*time.Second
	running, app, webUI = d.appRunning, d.app, d.webUI
	d.mu.Unlock()
	if fresh {
		return running, app, webUI
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	running = verge.Running(cctx, d.runner())
	app = nil
	if a, err := verge.FindApp(cctx, d.runner()); err == nil {
		app = &a
	}
	webUI = false
	if st, err := d.o.Verge.ReadSettings(); err == nil {
		webUI = slices.Contains(st.WebUIList, d.guiURL())
	}
	d.mu.Lock()
	d.appRunning, d.app, d.webUI, d.appChecked = running, app, webUI, time.Now()
	d.mu.Unlock()
	return running, app, webUI
}

// guiURL is the dashboard's plain address, as it goes into Verge's list.
func (d *Daemon) guiURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/", d.o.GUIPort)
}

// Built-in outbounds every rule may target.
var builtinTargets = []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}

// patchInputs is a copy of the daemon state an apply needs, taken under
// d.mu once so the lock is never held while files are written or the
// core is reloaded.
type patchInputs struct {
	runtime    verge.Runtime
	runtimeErr string
	strip      verge.Patch
	reachable  bool
	ruleSet    rules.Set
	liveMode   string
}

func (d *Daemon) inputs() patchInputs {
	d.mu.Lock()
	defer d.mu.Unlock()
	return patchInputs{runtime: d.runtime, runtimeErr: d.runtimeErr, strip: d.strip, reachable: d.mihomoVersion != "", ruleSet: d.ruleSet, liveMode: d.liveMode}
}

// buildPatch compiles set and assembles what goes into Verge's config:
// the rules, the imported nodes, the interface-bound outbounds, and the
// failover groups. Every rule target and group member must exist, either
// in the Verge profile that is running or in the patch itself; otherwise
// Verge's next apply would fail and leave the user without a proxy.
func (d *Daemon) buildPatch(in patchInputs, set rules.Set) (rules.Compiled, verge.Patch, []string, error) {
	c, err := rules.Compile(set)
	if err != nil {
		return rules.Compiled{}, verge.Patch{}, nil, err
	}
	if in.runtime.Config == nil {
		return rules.Compiled{}, verge.Patch{}, nil, fmt.Errorf("Clash Verge's runtime config isn't readable (%s), so the rules can't be checked against its proxies", firstNonEmpty(in.runtimeErr, "not read yet"))
	}
	var warnings []string
	nodes, err := vps.LoadNodes(d.path("nodes.yaml"))
	if err != nil {
		warnings = append(warnings, "imported nodes: "+err.Error())
	}

	// What the profile has on its own, with this daemon's earlier
	// contribution taken back out.
	base := verge.Strip(in.runtime.Config, in.strip)
	profileProxies, profileGroups := verge.Runtime{Config: base}.Names()
	known := map[string]bool{}
	for _, n := range slices.Concat(builtinTargets, profileProxies, profileGroups) {
		known[n] = true
	}

	p := verge.Patch{Rules: c.Rules, NameserverPolicy: c.NameserverPolicy}
	for _, px := range slices.Concat(vps.Proxies(nodes), c.Proxies) {
		name, _ := px["name"].(string)
		if known[name] {
			warnings = append(warnings, fmt.Sprintf("imported node %q skipped: your Clash Verge profile already has a proxy with that name", name))
			continue
		}
		known[name] = true
		p.Proxies = append(p.Proxies, px)
	}
	for _, g := range c.Groups {
		name, _ := g["name"].(string)
		if known[name] {
			warnings = append(warnings, fmt.Sprintf("group %q skipped: your Clash Verge profile already has a proxy or group with that name", name))
			continue
		}
		known[name] = true
		p.Groups = append(p.Groups, g)
	}
	for _, g := range p.Groups {
		members, _ := g["proxies"].([]any)
		for _, m := range members {
			if s, _ := m.(string); !known[s] {
				return rules.Compiled{}, verge.Patch{}, nil, fmt.Errorf("group %v: member %q is not a proxy or group in your Clash Verge profile", g["name"], s)
			}
		}
	}
	for _, line := range c.Rules {
		if _, target := splitRuleLine(line); !known[target] {
			return rules.Compiled{}, verge.Patch{}, nil, fmt.Errorf("rule %q: %q is not a proxy or group in your Clash Verge profile", line, target)
		}
	}
	return c, p, warnings, nil
}

// syncResult is what an apply found out, stored under d.mu afterwards.
type syncResult struct {
	pending bool // the Merge file is ahead of the core
	events  []string
}

// rejected reports whether an HTTP status from the core means it refused
// the config (as opposed to not being the core we think it is, or being
// in trouble): a 400-class reply other than auth and routing errors.
func rejected(status int) bool {
	return status >= 400 && status < 500 && status != http.StatusUnauthorized && status != http.StatusForbidden && status != http.StatusNotFound
}

// syncVerge writes the patch to Verge's Merge profile and hot-loads it
// into the running core. A core that rejects the config means Verge
// would reject it too, so the Merge file is put back and the error
// returned. A core that can't be reached keeps the Merge file: the rules
// apply when Verge next starts. No lock is held: this does file I/O and
// an HTTP call that may take a while.
func (d *Daemon) syncVerge(ctx context.Context, in patchInputs, p verge.Patch) (syncResult, error) {
	mergePath, err := d.o.Verge.MergeFile()
	if err != nil {
		return syncResult{}, err
	}
	prev, prevErr := verge.ReadMerge(mergePath)
	if err := verge.WriteMerge(mergePath, p); err != nil {
		return syncResult{}, fmt.Errorf("write Clash Verge's merge profile: %w", err)
	}
	if in.runtime.Config == nil || !in.reachable {
		return syncResult{pending: true, events: []string{"rules saved to Clash Verge's merge profile; they apply when Clash Verge starts"}}, nil
	}
	cfg, _ := verge.Apply(verge.Strip(in.runtime.Config, in.strip), p)
	// The runtime config carries the mode Verge last applied; a mode the
	// user switched since (here or in Verge) must survive the reload.
	if in.liveMode != "" {
		cfg["mode"] = in.liveMode
	}
	payload, err := yaml.Marshal(cfg)
	if err != nil {
		return syncResult{}, err
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := d.ctrl.reloadPayload(rctx, payload); err != nil {
		var herr *ctrlHTTPError
		if errors.As(err, &herr) && rejected(herr.Status) {
			rerr := fmt.Errorf("mihomo rejected the config: %s", herr.Msg)
			if prevErr != nil {
				return syncResult{}, fmt.Errorf("%w (and the merge profile couldn't be restored: it was unreadable before: %v)", rerr, prevErr)
			}
			if werr := verge.WriteMerge(mergePath, prev); werr != nil {
				return syncResult{}, fmt.Errorf("%w (and restoring the merge profile failed: %v)", rerr, werr)
			}
			return syncResult{}, rerr
		}
		return syncResult{pending: true, events: []string{fmt.Sprintf("couldn't hot-load the rules (%v); they are saved in Clash Verge's merge profile and apply when Clash Verge restarts", err)}}, nil
	}
	return syncResult{events: []string{"rules loaded into the running mihomo and saved to Clash Verge's merge profile"}}, nil
}

// finishSync records an apply's outcome. The caller holds d.mu.
func (d *Daemon) finishSync(ctx context.Context, res syncResult) {
	for _, e := range res.events {
		d.event("%s", e)
	}
	d.pendingRestart = res.pending
	if res.pending {
		d.rulesActive = false
		return
	}
	d.refreshRules(ctx)
}

// ApplyChange applies a change to the current rule set. Reading the set,
// applying the change, and saving happen under one apply lock, so two
// changes at once can't be built from the same base.
func (d *Daemon) ApplyChange(ctx context.Context, c rules.Change) error {
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	d.mu.Lock()
	next, err := d.ruleSet.Apply(c)
	d.mu.Unlock()
	if err != nil {
		return err
	}
	return d.applyRules(ctx, next)
}

// ApplyRules validates, saves, and applies a whole new rule set.
func (d *Daemon) ApplyRules(ctx context.Context, set rules.Set) error {
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	return d.applyRules(ctx, set)
}

// applyRules does the work of ApplyRules. The caller holds d.applyMu.
func (d *Daemon) applyRules(ctx context.Context, set rules.Set) error {
	in := d.inputs()
	c, p, warnings, err := d.buildPatch(in, set)
	if err != nil {
		return err
	}
	path := d.path("rules.yaml")
	if err := rules.Save(path, set); err != nil {
		return err
	}
	res, err := d.syncVerge(ctx, in, p)
	if err != nil {
		if rerr := rules.Save(path, in.ruleSet); rerr != nil {
			err = fmt.Errorf("%w (and restoring rules.yaml failed: %v)", err, rerr)
		}
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ruleSet, d.compiled, d.warnings = set, c, warnings
	d.finishSync(ctx, res)
	d.event("rules updated: %d user rules, packs %v", len(set.Rules), set.Packs)
	return nil
}

// ReloadConfig re-applies the saved rules and imported nodes, e.g. after
// a node was imported or removed, or when the user asks for the rules to
// be pushed into the core again.
func (d *Daemon) ReloadConfig(ctx context.Context) error {
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	in := d.inputs()
	c, p, warnings, err := d.buildPatch(in, in.ruleSet)
	if err != nil {
		return err
	}
	res, err := d.syncVerge(ctx, in, p)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.compiled, d.warnings = c, warnings
	d.finishSync(ctx, res)
	return nil
}

// RestartVerge quits and relaunches Clash Verge so it rebuilds its config
// from the profiles, including the Merge file this daemon writes.
func (d *Daemon) RestartVerge(ctx context.Context) error {
	err := verge.Restart(ctx, d.runner())
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.event("restarting Clash Verge failed: %v", err)
		return err
	}
	d.pendingRestart = false
	d.appChecked = time.Time{}
	d.event("Clash Verge restarted")
	return nil
}

// Propose records a rule change for a person to confirm, after checking
// that it would produce a valid config.
func (d *Daemon) Propose(origin, summary string, change rules.Change) (*Proposal, error) {
	in := d.inputs()
	next, err := in.ruleSet.Apply(change)
	if err == nil {
		_, _, _, err = d.buildPatch(in, next)
	}
	if err != nil {
		return nil, err
	}
	diff, err := in.ruleSet.Diff(change)
	if err != nil {
		return nil, err
	}
	p, err := d.proposals.Create(origin, summary, change, diff)
	if err == nil {
		d.mu.Lock()
		d.event("new %s proposal %s: %s", origin, p.ID, summary)
		d.mu.Unlock()
	}
	return p, err
}

// Decide applies or rejects a proposal.
func (d *Daemon) Decide(ctx context.Context, id string, accept bool) (Proposal, error) {
	return d.proposals.Decide(id, accept, func(c rules.Change) error {
		return d.ApplyChange(ctx, c)
	})
}

// refreshRules reads the core's rule list and works out whether this
// daemon's rules are at the front of it. The caller holds d.mu.
func (d *Daemon) refreshRules(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, err := d.ctrl.rules(rctx)
	if err != nil {
		return
	}
	d.ctrlRules = r
	d.rulesActive, d.sources = alignSources(r, d.compiled)
	if d.rulesActive {
		d.pendingRestart = false // the user restarted Verge themselves, or it re-applied
	}
}

// alignSources matches the core's rule list against the compiled rules.
// When the compiled rules are the first entries, they are labeled with
// their sources and the rest with the profile's; otherwise (Verge hasn't
// applied the Merge file, or a script rewrote the rules) everything is
// the profile's.
func alignSources(ctrl []ctrlRule, c rules.Compiled) (active bool, sources []rules.Source) {
	sources = make([]rules.Source, len(ctrl))
	n := len(c.Rules)
	active = len(ctrl) >= n
	for i := 0; i < n && active; i++ {
		payload, target := splitRuleLine(c.Rules[i])
		if ctrl[i].Payload != payload || ctrl[i].Proxy != target {
			active = false
		}
	}
	start := 0
	if active {
		copy(sources, c.Sources)
		start = n
	}
	for i := start; i < len(ctrl); i++ {
		sources[i] = rules.Source{Kind: "config", Index: i - start + 1}
	}
	return active, sources
}

// splitRuleLine returns the payload and target of a mihomo rule line.
func splitRuleLine(line string) (payload, target string) {
	_, rest, ok := strings.Cut(line, ",")
	if !ok {
		return "", ""
	}
	rest = strings.TrimSuffix(rest, ",no-resolve")
	i := strings.LastIndex(rest, ",")
	if i < 0 {
		return "", rest // MATCH,TARGET
	}
	return rest[:i], rest[i+1:]
}

// tunDevice is Verge's TUN device name, whether or not TUN is on.
func (d *Daemon) tunDevice() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.runtime.TUNDevice
}

func (d *Daemon) pollConnections(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			conns, err := d.ctrl.connections(pctx)
			cancel()
			if err == nil {
				d.tracker.Update(conns)
			}
		}
	}
}

func (d *Daemon) followLogs(ctx context.Context) {
	for ctx.Err() == nil {
		if d.ctrl.ready() {
			d.ctrl.streamLogs(ctx, "warning", d.tracker.AddLog)
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
}

// defaultInterface is the physical interface DIRECT traffic uses, cached
// briefly because it is looked up for every explanation.
func (d *Daemon) defaultInterface(ctx context.Context) string {
	d.ifaceMu.Lock()
	defer d.ifaceMu.Unlock()
	if time.Since(d.ifaceTime) > 10*time.Second {
		_, d.defIface = netstate.DefaultRoute(ctx, netstate.ExecRunner{})
		d.ifaceTime = time.Now()
	}
	return d.defIface
}

// event records something for the GUI. The caller holds d.mu.
func (d *Daemon) event(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	d.logf("%s", msg)
	d.events = append(d.events, Event{Time: time.Now(), Message: msg})
	if len(d.events) > 100 {
		d.events = d.events[len(d.events)-100:]
	}
}

func (d *Daemon) logf(format string, args ...any) {
	if d.o.Log != nil {
		d.o.Log.Printf(format, args...)
	}
}
