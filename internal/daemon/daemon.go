// Package daemon runs one Clash Mihomac instance: it starts mihomo in the
// requested mode, keeps its config in sync with the user's rules, tracks
// connections for diagnostics, and serves the localhost GUI and API.
//
// In port-only and system-proxy mode mihomo runs as the user, wrapped by
// `mihomac core-exec` so it dies with the daemon. In TUN mode the
// privileged helper runs it as root and ends the session if the daemon
// exits for any reason.
package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/gui"
	"github.com/nyaaorick/clash-mihomac/internal/health"
	"github.com/nyaaorick/clash-mihomac/internal/helper"
	"github.com/nyaaorick/clash-mihomac/internal/instance"
	"github.com/nyaaorick/clash-mihomac/internal/netstate"
	"github.com/nyaaorick/clash-mihomac/internal/rules"
	"github.com/nyaaorick/clash-mihomac/internal/runtimecfg"
	"github.com/nyaaorick/clash-mihomac/internal/vps"
)

// Options configure a daemon run.
type Options struct {
	Instance     instance.Instance
	Channel      string
	CorePath     string
	CoreVersion  string
	ConfigPath   string
	Mode         string
	RouteAddress []string // limit TUN capture (testing)
	HelperSocket string
	Exe          string // this mihomac binary, for the core-exec wrapper
	Log          *log.Logger
}

// Daemon is a running instance.
type Daemon struct {
	o         Options
	inst      instance.Instance
	ctrl      controller
	tracker   *Tracker
	proposals *Proposals
	health    *health.History
	traffic   *trafficState
	startedAt time.Time
	coreDied  chan error

	mu        sync.Mutex // held across mode switches and reloads
	mode      string
	core      runningCore
	ruleSet   rules.Set
	sources   []rules.Source
	ctrlRules []ctrlRule
	warnings  []string
	events    []Event

	ifaceMu   sync.Mutex
	defIface  string
	ifaceTime time.Time
}

// Event is something the daemon did, shown in the GUI.
type Event struct {
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

type runningCore interface {
	PID() int
	Exited() <-chan struct{} // nil if the daemon can't observe the process
	Stop(ctx context.Context) string
}

// Run starts the instance and blocks until ctx is cancelled or the core
// dies. The core is always stopped, and the network restored, before Run
// returns.
func Run(ctx context.Context, o Options) error {
	secret, err := randomHex(32)
	if err != nil {
		return err
	}
	inst := o.Instance
	if err := os.MkdirAll(inst.Dir, 0o700); err != nil {
		return err
	}
	d := &Daemon{
		o: o, inst: inst,
		ctrl:      controller{addr: fmt.Sprintf("127.0.0.1:%d", inst.ControllerPort), secret: secret},
		tracker:   NewTracker(),
		proposals: LoadProposals(inst.Path("proposals.json")),
		health:    health.LoadHistory(inst.Path("health.json")),
		coreDied:  make(chan error, 1),
	}
	d.initTraffic()

	// Claim the GUI port first so a port clash fails before anything changes.
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", inst.GUIPort))
	if err != nil {
		return fmt.Errorf("GUI port: %w", err)
	}
	defer ln.Close()
	full, err := gui.LoadOrCreateToken(inst.Path("gui-token"))
	if err != nil {
		return err
	}
	agent, err := gui.LoadOrCreateToken(inst.Path("mcp-token"))
	if err != nil {
		return err
	}

	d.mu.Lock()
	err = d.start(ctx, o.Mode)
	d.mu.Unlock()
	if err != nil {
		return err
	}
	defer d.shutdown()

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

	d.mu.Lock()
	err = d.saveState()
	d.mu.Unlock()
	if err != nil {
		return err
	}
	defer removeState(inst)

	go d.pollConnections(ctx)
	go d.followLogs(ctx)
	go d.monitorHealth(ctx)
	go d.pollTraffic(ctx)

	health := time.NewTicker(2 * time.Second)
	defer health.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			d.logf("shutting down")
			return nil
		case err := <-d.coreDied:
			return err
		case <-health.C:
			hctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, err := d.ctrl.version(hctx)
			cancel()
			if err == nil {
				failures = 0
				continue
			}
			if failures++; failures >= 5 {
				return fmt.Errorf("mihomo stopped responding: %v", err)
			}
		}
	}
}

// start brings the core up in mode. The caller holds d.mu.
func (d *Daemon) start(ctx context.Context, mode string) error {
	set, err := rules.Load(d.inst.Path("rules.yaml"))
	if err != nil {
		return err
	}
	res, err := d.build(mode, set)
	if err != nil {
		return err
	}
	for _, w := range res.Warnings {
		d.logf("config: %s", w)
	}

	var core runningCore
	if mode == runtimecfg.ModeTUN {
		bin, err := os.Open(d.o.CorePath)
		if err != nil {
			return err
		}
		var r helper.TUNStartResult
		err = d.helperCall(ctx, "tun-start", helper.TUNStartArgs{Instance: d.inst.Name, Config: string(res.Config)}, &r, bin)
		bin.Close()
		if err != nil {
			return fmt.Errorf("start TUN: %w", err)
		}
		core = &helperCore{d: d, pid: r.CorePID}
	} else {
		if err := os.WriteFile(d.inst.Path("runtime.yaml"), res.Config, 0o600); err != nil {
			return err
		}
		lc, err := d.startLocal()
		if err != nil {
			return err
		}
		core = lc
	}

	if err := d.ctrl.waitReady(ctx, core.Exited(), 15*time.Second); err != nil {
		core.Stop(context.Background())
		return fmt.Errorf("%w (see %s)", err, d.coreLog(mode))
	}
	if mode == runtimecfg.ModeSystemProxy {
		if err := d.helperCall(ctx, "sysproxy-set", helper.InstanceArgs{Instance: d.inst.Name}, nil); err != nil {
			core.Stop(context.Background())
			return fmt.Errorf("set system proxy: %w", err)
		}
	}

	d.mode, d.core, d.ruleSet, d.sources, d.warnings = mode, core, set, res.Sources, res.Warnings
	d.refreshRules(ctx)
	d.event("started in %s mode (core pid %d)", mode, core.PID())
	return nil
}

// stop takes the core down and undoes system changes. The caller holds d.mu.
func (d *Daemon) stop(ctx context.Context) {
	if d.core == nil {
		return
	}
	if d.mode == runtimecfg.ModeSystemProxy {
		var ev helper.Event
		if err := d.helperCall(ctx, "sysproxy-clear", helper.InstanceArgs{Instance: d.inst.Name}, &ev); err != nil {
			d.event("clearing system proxy failed: %v (the helper restores it when this daemon exits)", err)
		} else {
			d.event("%s", ev.Message)
		}
	}
	if note := d.core.Stop(ctx); note != "" {
		d.event("%s", note)
	}
	d.core = nil
	d.tracker.Reset()
}

func (d *Daemon) shutdown() {
	d.mu.Lock()
	defer d.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d.stop(ctx)
}

// SetMode restarts the core in a new mode, falling back to the previous
// mode if the new one fails.
func (d *Daemon) SetMode(ctx context.Context, mode string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if mode == d.mode && d.core != nil {
		return nil
	}
	prev := d.mode
	d.stop(ctx)
	if err := d.start(ctx, mode); err != nil {
		d.event("switching to %s failed: %v; returning to %s", mode, err, prev)
		if err2 := d.start(ctx, prev); err2 != nil {
			select {
			case d.coreDied <- fmt.Errorf("could not restore %s mode: %w", prev, err2):
			default:
			}
		}
		return err
	}
	return d.saveState()
}

// ApplyRules validates, saves, and hot-reloads a new rule set.
func (d *Daemon) ApplyRules(ctx context.Context, set rules.Set) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.build(d.mode, set)
	if err != nil {
		return err
	}
	path := d.inst.Path("rules.yaml")
	old, _ := rules.Load(path)
	if err := rules.Save(path, set); err != nil {
		return err
	}
	if err := d.reload(ctx, res.Config); err != nil {
		rules.Save(path, old)
		return err
	}
	d.ruleSet, d.sources, d.warnings = set, res.Sources, res.Warnings
	d.refreshRules(ctx)
	d.event("rules updated: %d user rules, packs %v", len(set.Rules), set.Packs)
	return nil
}

// ReloadConfig rebuilds the runtime config from the saved rules and
// imported nodes and hot-reloads it, e.g. after a node was imported.
func (d *Daemon) ReloadConfig(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.build(d.mode, d.ruleSet)
	if err != nil {
		return err
	}
	if err := d.reload(ctx, res.Config); err != nil {
		return err
	}
	d.sources, d.warnings = res.Sources, res.Warnings
	d.refreshRules(ctx)
	return nil
}

func (d *Daemon) reload(ctx context.Context, cfg []byte) error {
	if d.mode == runtimecfg.ModeTUN {
		return d.helperCall(ctx, "tun-reload", helper.TUNReloadArgs{Instance: d.inst.Name, Config: string(cfg)}, nil)
	}
	path := d.inst.Path("runtime.yaml")
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		return err
	}
	return d.ctrl.reload(ctx, path)
}

// build renders the runtime config for mode and set.
func (d *Daemon) build(mode string, set rules.Set) (runtimecfg.Result, error) {
	user, err := os.ReadFile(d.o.ConfigPath)
	if err != nil {
		return runtimecfg.Result{}, err
	}
	compiled, err := rules.Compile(set)
	if err != nil {
		return runtimecfg.Result{}, err
	}
	var extra []map[string]any
	if nodes, err := vps.LoadNodes(d.inst.Path("nodes.yaml")); err == nil {
		extra = vps.Proxies(nodes)
	}
	return runtimecfg.Build(user, runtimecfg.Options{ExtraProxies: extra,
		MixedPort: d.inst.MixedPort, ControllerPort: d.inst.ControllerPort, Secret: d.ctrl.secret,
		Mode: mode, TUNDevice: d.inst.TUNDevice, TUNAddress: d.inst.TUNAddress, RouteAddress: d.o.RouteAddress, Rules: &compiled,
	})
}

// Propose records a rule change for a person to confirm, after checking
// that it would produce a valid config.
func (d *Daemon) Propose(origin, summary string, change rules.Change) (*Proposal, error) {
	d.mu.Lock()
	current, mode := d.ruleSet, d.mode
	d.mu.Unlock()
	next, err := current.Apply(change)
	if err != nil {
		return nil, err
	}
	if _, err := d.build(mode, next); err != nil {
		return nil, err
	}
	diff, err := current.Diff(change)
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
		d.mu.Lock()
		next, err := d.ruleSet.Apply(c)
		d.mu.Unlock()
		if err != nil {
			return err
		}
		return d.ApplyRules(ctx, next)
	})
}

func (d *Daemon) refreshRules(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if r, err := d.ctrl.rules(rctx); err == nil {
		d.ctrlRules = r
	}
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
		d.ctrl.streamLogs(ctx, "warning", d.tracker.AddLog)
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

func (d *Daemon) helperCall(ctx context.Context, cmd string, args, out any, files ...*os.File) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return helper.Call(ctx, d.o.HelperSocket, cmd, args, out, files...)
}

// saveState records the running instance. The caller holds d.mu.
func (d *Daemon) saveState() error {
	pid := 0
	if d.core != nil {
		pid = d.core.PID()
	}
	return writeState(d.inst, State{
		Instance: d.inst.Name, PID: os.Getpid(), CorePID: pid, Mode: d.mode,
		CoreVersion: d.o.CoreVersion, ConfigPath: d.o.ConfigPath,
		MixedPort: d.inst.MixedPort, ControllerPort: d.inst.ControllerPort,
		GUIURL: fmt.Sprintf("http://127.0.0.1:%d/", d.inst.GUIPort), StartedAt: d.startedAt,
	})
}

func (d *Daemon) coreLog(mode string) string {
	if mode == runtimecfg.ModeTUN {
		return "the helper's log for " + d.inst.Name
	}
	return d.inst.Path("mihomo.log")
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

func (d *Daemon) logf(format string, args ...any) { d.o.Log.Printf(format, args...) }

// localCore is mihomo running as the user under the core-exec wrapper.
type localCore struct {
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	exited   chan struct{}
	stopping atomic.Bool
}

func (d *Daemon) startLocal() (*localCore, error) {
	logf, err := os.OpenFile(d.inst.Path("mihomo.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer logf.Close()
	cmd := exec.Command(d.o.Exe, "core-exec", d.o.CorePath, "-d", d.inst.Dir, "-f", d.inst.Path("runtime.yaml"))
	cmd.Stdout, cmd.Stderr = logf, logf
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start mihomo: %w", err)
	}
	c := &localCore{cmd: cmd, stdin: stdin, exited: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		close(c.exited)
		if !c.stopping.Load() {
			select {
			case d.coreDied <- fmt.Errorf("mihomo exited unexpectedly: %v (see %s)", err, d.inst.Path("mihomo.log")):
			default:
			}
		}
	}()
	return c, nil
}

func (c *localCore) PID() int                { return c.cmd.Process.Pid }
func (c *localCore) Exited() <-chan struct{} { return c.exited }
func (c *localCore) Stop(context.Context) string {
	c.stopping.Store(true)
	c.stdin.Close() // the wrapper stops mihomo on EOF
	c.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-c.exited:
	case <-time.After(8 * time.Second):
		c.cmd.Process.Kill()
		<-c.exited
	}
	return "mihomo stopped"
}

// helperCore is mihomo running as root under the privileged helper.
type helperCore struct {
	d   *Daemon
	pid int
}

func (c *helperCore) PID() int                { return c.pid }
func (c *helperCore) Exited() <-chan struct{} { return nil }
func (c *helperCore) Stop(ctx context.Context) string {
	var ev helper.Event
	if err := c.d.helperCall(ctx, "tun-stop", helper.InstanceArgs{Instance: c.d.inst.Name}, &ev); err != nil {
		return fmt.Sprintf("stopping TUN via the helper failed: %v (the helper stops it when this daemon exits)", err)
	}
	return ev.Message
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
