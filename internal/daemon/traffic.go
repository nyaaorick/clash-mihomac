package daemon

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/gui"
	"github.com/nyaaorick/clash-mihomac/internal/health"
	"github.com/nyaaorick/clash-mihomac/internal/helper"
	"github.com/nyaaorick/clash-mihomac/internal/netstate"
	"github.com/nyaaorick/clash-mihomac/internal/runtimecfg"
	"github.com/nyaaorick/clash-mihomac/internal/traffic"
)

// Traffic polling.
const (
	trafficInterval   = 3 * time.Second
	counterRingSpan   = time.Hour
	counterRingStep   = 5 * time.Second
	nodeAddrTTL       = 10 * time.Minute
	stableBeforeAlert = 2 // polls a bypass must persist before it is reported
)

// trafficState is the traffic view's working data, rebuilt every poll.
type trafficState struct {
	mu        sync.Mutex
	store     *traffic.Store
	collector *traffic.Collector

	flows    []traffic.Flow // open flows from the last poll
	state    traffic.SystemState
	ownTUN   string
	seenOnce map[string]int // flow ID → consecutive polls its anomalies were seen
	ring     []counterSnap  // interface counters over time, oldest first
	updated  time.Time

	addrs map[string]nodeAddrEntry
}

type counterSnap struct {
	t time.Time
	c map[string]traffic.IfaceCounters
}

type nodeAddrEntry struct {
	at    time.Time
	addrs []netip.Addr
}

// helperSockets reads the socket table through the privileged helper,
// which sees every process; without the helper it falls back to lsof.
type helperSockets struct {
	d        *Daemon
	fallback traffic.SocketSource
}

func (h helperSockets) Sockets(ctx context.Context) ([]traffic.Socket, error) {
	var res helper.SocketsResult
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := h.d.helperCall(cctx, "sockets", struct{}{}, &res); err == nil {
		return res.Sockets, nil
	}
	return h.fallback.Sockets(ctx)
}

func (d *Daemon) initTraffic() {
	run := netstate.ExecRunner{}
	d.traffic = &trafficState{
		store:     traffic.OpenStore(d.inst.Path("traffic-history.jsonl"), traffic.DefaultRetention),
		collector: &traffic.Collector{Run: run},
		seenOnce:  map[string]int{},
		addrs:     map[string]nodeAddrEntry{},
	}
	d.traffic.collector.Sockets = helperSockets{d: d, fallback: traffic.LsofSockets{Run: run}}
}

// pollTraffic builds the flow view every few seconds.
func (d *Daemon) pollTraffic(ctx context.Context) {
	t := time.NewTicker(trafficInterval)
	defer t.Stop()
	flush := time.NewTicker(15 * time.Second)
	defer flush.Stop()
	compact := time.NewTicker(time.Hour)
	defer compact.Stop()
	d.pollTrafficOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			d.traffic.store.Flush()
			return
		case <-t.C:
			d.pollTrafficOnce(ctx)
		case <-flush.C:
			if err := d.traffic.store.Flush(); err != nil {
				d.logf("save traffic history: %v", err)
			}
		case <-compact.C:
			d.traffic.store.Compact()
		}
	}
}

func (d *Daemon) pollTrafficOnce(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tr := d.traffic

	d.mu.Lock()
	mode, corePID := d.mode, 0
	if d.core != nil {
		corePID = d.core.PID()
	}
	d.mu.Unlock()

	state := tr.collector.Read(pctx)
	own := ""
	if mode == runtimecfg.ModeTUN {
		own = d.inst.TUNDevice
	}

	var conns []traffic.Conn
	for _, c := range d.tracker.List("", 5000) {
		if c.End != nil {
			continue
		}
		conns = append(conns, traffic.Conn{
			ID: c.ID, Start: c.Start, Network: c.Network, Inbound: c.Inbound, Source: c.Source,
			Host: c.Host, DestIP: c.DestIP, DestPort: c.DestPort, Process: c.Process, ProcessPath: c.ProcessPath,
			Rule: c.Rule, RulePayload: c.RulePayload, Chains: c.Chains, Upload: c.Upload, Download: c.Download,
		})
	}

	flows := traffic.Join(traffic.Inputs{
		Time: state.Time, Conns: conns, Sockets: state.Sockets, Routes: state.Routes, PS: state.PS,
		TUNMode: mode == runtimecfg.ModeTUN, OwnTUN: own, DefaultIface: d.defaultInterface(pctx),
		AddrOwner: state.AddrOwner, NodeAddrs: d.nodeAddrs, IgnorePIDs: []int{corePID},
	})
	tr.collector.Enrich(pctx, flows)

	tr.mu.Lock()
	defer tr.mu.Unlock()
	flows = tr.stabilize(flows)
	tr.flows, tr.state, tr.ownTUN, tr.updated = flows, state, own, state.Time
	tr.store.Observe(flows)
	tr.recordCounters(state)
}

// stabilize drops path anomalies that appear for only one poll. A new
// connection can show up in the socket table a moment before mihomo lists
// it, which would otherwise look like traffic that bypassed TUN.
func (tr *trafficState) stabilize(flows []traffic.Flow) []traffic.Flow {
	seen := map[string]int{}
	for i := range flows {
		f := &flows[i]
		if len(f.Anomalies) == 0 {
			continue
		}
		seen[f.ID] = tr.seenOnce[f.ID] + 1
		if seen[f.ID] < stableBeforeAlert {
			f.Anomalies = nil
		}
	}
	tr.seenOnce = seen
	return flows
}

func (tr *trafficState) recordCounters(st traffic.SystemState) {
	if st.Counters == nil {
		return
	}
	if n := len(tr.ring); n > 0 && st.Time.Sub(tr.ring[n-1].t) < counterRingStep {
		return
	}
	tr.ring = append(tr.ring, counterSnap{t: st.Time, c: st.Counters})
	cutoff := st.Time.Add(-counterRingSpan)
	i := 0
	for i < len(tr.ring)-1 && tr.ring[i].t.Before(cutoff) {
		i++
	}
	tr.ring = tr.ring[i:]
}

// counterWindow returns the delta over roughly the last window, and the
// span it actually covers.
func (tr *trafficState) counterWindow(window time.Duration) (map[string]traffic.IfaceCounters, time.Duration, bool) {
	if len(tr.ring) < 2 {
		return nil, 0, false
	}
	last := tr.ring[len(tr.ring)-1]
	base := tr.ring[0]
	for _, s := range tr.ring {
		if last.t.Sub(s.t) >= window {
			base = s
		} else {
			break
		}
	}
	return traffic.Delta(base.c, last.c), last.t.Sub(base.t), true
}

// nodeAddrs resolves a proxy node's server for the egress lookup, caching
// the answers. Unresolvable nodes fall back to the default interface.
func (d *Daemon) nodeAddrs(node string) []netip.Addr {
	tr := d.traffic
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if e, ok := tr.addrs[node]; ok && time.Since(e.at) < nodeAddrTTL {
		return e.addrs
	}
	var addrs []netip.Addr
	if cfg, err := os.ReadFile(d.o.ConfigPath); err == nil {
		if targets, err := health.TargetsFromConfig(cfg); err == nil {
			for _, t := range targets {
				if t.Name != node {
					continue
				}
				if a, err := netip.ParseAddr(t.Server); err == nil {
					addrs = []netip.Addr{a}
				} else {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					if ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", t.Server); err == nil {
						addrs = ips
					}
					cancel()
				}
			}
		}
	}
	tr.addrs[node] = nodeAddrEntry{at: time.Now(), addrs: addrs}
	return addrs
}

// ---- API ----

// TrafficView is GET /api/traffic.
type TrafficView struct {
	Mode      string           `json:"mode"` // live or history
	Updated   time.Time        `json:"updated"`
	Sankey    traffic.Sankey   `json:"sankey"`
	Processes []traffic.Rollup `json:"processes"`
	Anomalies []FlowAnomaly    `json:"anomalies"`
	Flows     int              `json:"flows"`
	Warnings  []string         `json:"warnings,omitempty"`
	TUN       string           `json:"tun,omitempty"`
}

// FlowAnomaly is a surprise on one flow's path.
type FlowAnomaly struct {
	Flow    string `json:"flow"`
	Process string `json:"process"`
	Remote  string `json:"remote"`
	Kind    string `json:"kind"`
	Detail  string `json:"detail"`
}

func parseFilter(r *http.Request) (traffic.Filter, string) {
	q := r.URL.Query()
	f := traffic.Filter{
		Process: q.Get("process"), Proto: q.Get("proto"), Iface: q.Get("iface"),
		Rule: q.Get("rule"), Node: q.Get("node"), Routing: q.Get("routing"),
		Listening: q.Get("listening") == "1",
	}
	mode := "live"
	if q.Get("mode") == "history" {
		mode = "history"
		span := 15 * time.Minute
		if d, err := time.ParseDuration(q.Get("range")); err == nil && d > 0 && d <= 7*24*time.Hour {
			span = d
		}
		f.Since = time.Now().Add(-span)
	}
	return f, mode
}

// source returns the flows for a mode.
func (tr *trafficState) source(mode string, f traffic.Filter) []traffic.Flow {
	if mode == "history" {
		return f.Apply(tr.store.Since(f.Since))
	}
	tr.mu.Lock()
	flows := append([]traffic.Flow(nil), tr.flows...)
	tr.mu.Unlock()
	return f.Apply(flows)
}

func (d *Daemon) handleTraffic(w http.ResponseWriter, r *http.Request) {
	f, mode := parseFilter(r)
	view := traffic.View(r.URL.Query().Get("view"))
	perLayer, _ := strconv.Atoi(r.URL.Query().Get("nodes"))
	flows := d.traffic.source(mode, f)

	tr := d.traffic
	tr.mu.Lock()
	out := TrafficView{Mode: mode, Updated: tr.updated, Warnings: tr.state.Warnings, TUN: tr.ownTUN}
	tr.mu.Unlock()
	out.Sankey = traffic.BuildSankey(flows, view, perLayer)
	out.Processes = traffic.RollupByProcess(flows)
	out.Flows = len(flows)
	out.Anomalies = []FlowAnomaly{}
	for _, fl := range flows {
		for _, a := range fl.Anomalies {
			out.Anomalies = append(out.Anomalies, FlowAnomaly{Flow: fl.ID, Process: traffic.AppName(fl.Process), Remote: fl.Remote, Kind: a.Kind, Detail: a.Detail})
		}
	}
	writeJSON(w, out)
}

func (d *Daemon) handleTrafficFlows(w http.ResponseWriter, r *http.Request) {
	f, mode := parseFilter(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	flows := d.traffic.source(mode, f)
	sort.SliceStable(flows, func(i, j int) bool { return flows[i].Bytes() > flows[j].Bytes() })
	if len(flows) > limit {
		flows = flows[:limit]
	}
	if flows == nil {
		flows = []traffic.Flow{}
	}
	writeJSON(w, flows)
}

// TrafficInterface is one interface in the hardware inventory.
type TrafficInterface struct {
	Iface
	Rate   *traffic.IfaceRate `json:"rate,omitempty"`
	Routes []string           `json:"route_list,omitempty"` // destinations it owns
}

// TrafficInterfaces is GET /api/traffic/interfaces.
type TrafficInterfaces struct {
	Interfaces []TrafficInterface     `json:"interfaces"`
	Reconcile  traffic.Reconciliation `json:"reconcile"`
}

func (d *Daemon) handleTrafficInterfaces(w http.ResponseWriter, r *http.Request) {
	ifs, err := Interfaces(r.Context(), netstate.ExecRunner{}, d.inst.TUNDevice)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	window := time.Minute
	if v, err := time.ParseDuration(r.URL.Query().Get("window")); err == nil && v >= 5*time.Second && v <= time.Hour {
		window = v
	}

	tr := d.traffic
	tr.mu.Lock()
	delta, span, ok := tr.counterWindow(window)
	var totals map[string]traffic.IfaceCounters
	if ok {
		totals = tr.ring[len(tr.ring)-1].c
	}
	flows := append([]traffic.Flow(nil), tr.flows...)
	own := tr.ownTUN
	routes := tr.state.Routes
	tr.mu.Unlock()

	rates := map[string]traffic.IfaceRate{}
	if ok {
		for _, rt := range traffic.Rates(delta, totals, span) {
			rates[rt.Name] = rt
		}
	}
	out := TrafficInterfaces{Interfaces: []TrafficInterface{}}
	for _, i := range ifs {
		ti := TrafficInterface{Iface: i}
		if rt, ok := rates[i.Name]; ok {
			ti.Rate = &rt
		}
		ti.Routes = routes.DestinationsVia(i.Name, 30)
		out.Interfaces = append(out.Interfaces, ti)
	}
	if ok {
		out.Reconcile = traffic.Reconcile(delta, own, flows, span)
	} else {
		out.Reconcile = traffic.Reconciliation{Notes: []string{"Collecting counters; check back in a few seconds."}}
	}
	writeJSON(w, out)
}

func (d *Daemon) handleTrafficClear(w http.ResponseWriter, r *http.Request) {
	if gui.ScopeFrom(r.Context()) != gui.ScopeFull {
		httpError(w, http.StatusForbidden, ErrAgentForbidden.Error())
		return
	}
	if err := d.traffic.store.Clear(); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"cleared": true})
}
