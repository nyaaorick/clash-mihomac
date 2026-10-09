package daemon

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/health"
	"github.com/nyaaorick/clash-mihomac/internal/rules"
	"github.com/nyaaorick/clash-mihomac/internal/vps"
)

// Health-check timing.
const (
	healthInterval    = 2 * time.Minute
	healthFirstDelay  = 15 * time.Second
	healthConcurrency = 6
	healthTimeout     = 5 * time.Second
)

// ctrlDelayer measures latency through a node with mihomo's delay test.
type ctrlDelayer struct {
	c   controller
	url string
}

func (d ctrlDelayer) Delay(ctx context.Context, node string) (time.Duration, error) {
	return d.c.delay(ctx, node, d.url, healthTimeout)
}

// monitorHealth checks every proxy node in the user's config on a schedule.
func (d *Daemon) monitorHealth(ctx context.Context) {
	timer := time.NewTimer(healthFirstDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			d.health.Save()
			return
		case <-timer.C:
		}
		d.checkNodes(ctx, "")
		timer.Reset(healthInterval)
	}
}

var healthRun sync.Mutex // one round of checks at a time

// checkNodes runs a health round over all nodes, or only the named one.
// It returns the nodes checked.
func (d *Daemon) checkNodes(ctx context.Context, only string) []string {
	healthRun.Lock()
	defer healthRun.Unlock()

	targets, err := d.nodeTargets()
	if err != nil {
		return nil
	}
	keep := map[string]bool{}
	for _, t := range targets {
		keep[t.Name] = true
	}
	if only == "" {
		d.health.Forget(keep)
	} else {
		targets = filterTargets(targets, only)
	}

	checker := &health.Checker{
		Net:     health.SysNet{Interface: d.defaultInterface(ctx)},
		Delayer: ctrlDelayer{c: d.ctrl, url: rules.DefaultGroupURL},
		Timeout: healthTimeout,
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, healthConcurrency)
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res := checker.Check(ctx, t)
			d.health.Record(res)
			if !res.OK {
				d.mu.Lock()
				d.event("node %s failed its health check (%s): %s", t.Name, res.Kind, res.Detail)
				d.mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if err := d.health.Save(); err != nil {
		d.logf("save health history: %v", err)
	}
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = t.Name
	}
	return names
}

// nodeTargets lists every proxy node to check: those in the user's config
// and those imported from share links or managed servers.
func (d *Daemon) nodeTargets() ([]health.Target, error) {
	targets, err := d.userTargets()
	if err != nil {
		return nil, err
	}
	if nodes, err := vps.LoadNodes(d.inst.Path("nodes.yaml")); err == nil {
		targets = append(targets, health.TargetsFromProxies(vps.Proxies(nodes))...)
	}
	return targets, nil
}

// userTargets lists the proxy nodes in the user's own config file.
func (d *Daemon) userTargets() ([]health.Target, error) {
	cfg, err := os.ReadFile(d.o.ConfigPath)
	if err != nil {
		return nil, err
	}
	return health.TargetsFromConfig(cfg)
}

func filterTargets(ts []health.Target, name string) []health.Target {
	for _, t := range ts {
		if t.Name == name {
			return []health.Target{t}
		}
	}
	return nil
}

// HealthView is GET /api/health.
type HealthView struct {
	Nodes    []health.Summary `json:"nodes"`
	Overview []string         `json:"overview"`
	Interval int              `json:"interval_seconds"`
}

func (d *Daemon) healthView() HealthView {
	names := d.health.Nodes()
	v := HealthView{Nodes: make([]health.Summary, 0, len(names)), Overview: []string{}, Interval: int(healthInterval / time.Second)}
	for _, n := range names {
		v.Nodes = append(v.Nodes, d.health.Summary(n))
	}
	sort.Slice(v.Nodes, func(i, j int) bool { return v.Nodes[i].Node < v.Nodes[j].Node })
	v.Overview = append(v.Overview, health.Overview(v.Nodes)...)
	return v
}

func (d *Daemon) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, d.healthView())
}

// NodeHealth is GET /api/health/{node}.
type NodeHealth struct {
	Summary health.Summary `json:"summary"`
	Checks  []health.Check `json:"checks"` // newest first
}

func (d *Daemon) handleNodeHealth(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("node")
	cs := d.health.Checks(name)
	if len(cs) == 0 {
		httpError(w, http.StatusNotFound, "no health history for "+name)
		return
	}
	out := NodeHealth{Summary: d.health.Summary(name), Checks: make([]health.Check, len(cs))}
	for i, c := range cs {
		out.Checks[len(cs)-1-i] = c
	}
	writeJSON(w, out)
}

// handleHealthCheck runs a round of checks now (POST /api/health/check).
func (d *Daemon) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Node string `json:"node"`
	}
	if r.ContentLength != 0 && !readJSON(w, r, &body) {
		return
	}
	names := d.checkNodes(r.Context(), body.Node)
	if body.Node != "" && len(names) == 0 {
		httpError(w, http.StatusNotFound, errors.New("no proxy node named "+body.Node+" in your config").Error())
		return
	}
	writeJSON(w, d.healthView())
}
