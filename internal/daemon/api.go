package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/gui"
	"github.com/nyaaorick/clash-mihomac/internal/health"
	"github.com/nyaaorick/clash-mihomac/internal/netstate"
	"github.com/nyaaorick/clash-mihomac/internal/rules"
	"github.com/nyaaorick/clash-mihomac/internal/verge"
)

// api returns the /api/ handlers. Authentication and scopes are enforced
// by the gui package before these run.
func (d *Daemon) api() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", d.handleStatus)
	mux.HandleFunc("POST /api/verge/restart", d.handleVergeRestart)
	mux.HandleFunc("POST /api/verge/apply", d.handleVergeApply)
	mux.HandleFunc("POST /api/verge/mode", d.handleVergeMode)
	mux.HandleFunc("GET /api/connections", d.handleConnections)
	mux.HandleFunc("GET /api/connections/{id}", d.handleConnection)
	mux.HandleFunc("POST /api/probe", d.handleProbe)
	mux.HandleFunc("GET /api/rules", d.handleRules)
	mux.HandleFunc("POST /api/rules/change", d.handleRuleChange)
	mux.HandleFunc("POST /api/packs/preview", d.handlePackPreview)
	mux.HandleFunc("POST /api/rules/preview", d.handleRulesPreview)
	mux.HandleFunc("GET /api/proposals", d.handleProposals)
	mux.HandleFunc("POST /api/proposals", d.handlePropose)
	mux.HandleFunc("POST /api/proposals/{id}/{decision}", d.handleDecide)
	mux.HandleFunc("GET /api/interfaces", d.handleInterfaces)
	mux.HandleFunc("GET /api/nodes", d.handleNodes)
	mux.HandleFunc("GET /api/apps", d.handleApps)
	mux.HandleFunc("GET /api/health", d.handleHealth)
	mux.HandleFunc("GET /api/health/{node}", d.handleNodeHealth)
	mux.HandleFunc("POST /api/health/check", d.handleHealthCheck)
	mux.HandleFunc("GET /api/traffic", d.handleTraffic)
	mux.HandleFunc("GET /api/traffic/flows", d.handleTrafficFlows)
	mux.HandleFunc("GET /api/traffic/interfaces", d.handleTrafficInterfaces)
	mux.HandleFunc("POST /api/traffic/clear", d.handleTrafficClear)
	mux.HandleFunc("POST /api/vps/preflight", d.handleVPSPreflight)
	mux.HandleFunc("POST /api/vps/setup", d.handleVPSSetup)
	mux.HandleFunc("GET /api/vps/jobs/{id}", d.handleVPSJob)
	mux.HandleFunc("GET /api/vps/machines", d.handleVPSMachines)
	mux.HandleFunc("POST /api/vps/machines/{id}/check", d.handleVPSCheck)
	mux.HandleFunc("POST /api/vps/machines/{id}/quota", d.handleVPSQuota)
	mux.HandleFunc("POST /api/vps/machines/{id}/preview", d.handleVPSActionPreview)
	mux.HandleFunc("POST /api/vps/machines/{id}/run", d.handleVPSActionRun)
	mux.HandleFunc("POST /api/vps/machines/{id}/disable-password", d.handleVPSDisablePassword)
	mux.HandleFunc("POST /api/vps/machines/{id}/remove", d.handleVPSRemove)
	mux.HandleFunc("GET /api/vps/machines/{id}/share", d.handleVPSShare)
	mux.HandleFunc("POST /api/vps/import", d.handleVPSImport)
	mux.HandleFunc("POST /api/vps/import/apply", d.handleVPSImportApply)
	mux.HandleFunc("GET /api/logs", d.handleLogs)
	return mux
}

// Status is GET /api/status.
type Status struct {
	Channel        string         `json:"channel"`
	StartedAt      time.Time      `json:"started_at"`
	Verge          VergeStatus    `json:"verge"`
	HasRules       bool           `json:"has_rules"`       // the user has rules, packs, groups, or imported nodes
	RulesActive    bool           `json:"rules_active"`    // the running core has this daemon's rules
	PendingRestart bool           `json:"pending_restart"` // the Merge file is ahead of the core
	Rules          map[string]int `json:"rules"`
	Warnings       []string       `json:"warnings"`
	Events         []Event        `json:"events"`
	WebUIURL       string         `json:"webui_url,omitempty"` // full scope only: carries the token
}

// VergeStatus is what the daemon knows about Clash Verge and its core.
type VergeStatus struct {
	Dir           string     `json:"dir"`
	App           *verge.App `json:"app,omitempty"` // nil when no installed app was found
	AppRunning    bool       `json:"app_running"`
	ConfigError   string     `json:"config_error,omitempty"`
	Controller    string     `json:"controller"`
	MihomoVersion string     `json:"mihomo_version,omitempty"` // empty while unreachable
	MixedPort     int        `json:"mixed_port"`
	Mode          string     `json:"mode"`  // the core's running mode
	Modes         []string   `json:"modes"` // what it can be switched to
	TUN           bool       `json:"tun"`
	TUNDevice     string     `json:"tun_device"`
	MergeFile     string     `json:"merge_file"`
	WebUI         bool       `json:"webui"` // the GUI is in Verge's Settings → Web UI list
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	appRunning, app, webUI := d.vergeState(r.Context())
	mergeFile, _ := d.o.Verge.MergeFile()

	d.mu.Lock()
	defer d.mu.Unlock()
	counts := map[string]int{}
	for _, s := range d.sources {
		counts[s.Kind]++
	}
	st := Status{
		Channel: d.o.Channel, StartedAt: d.startedAt,
		Verge: VergeStatus{
			Dir: string(d.o.Verge), App: app, AppRunning: appRunning, ConfigError: d.runtimeErr,
			Controller: d.ctrl.endpoint().String(), MihomoVersion: d.mihomoVersion,
			MixedPort: d.runtime.MixedPort, Mode: firstNonEmpty(d.liveMode, d.runtime.Mode), Modes: Modes, TUN: d.runtime.TUN, TUNDevice: d.runtime.TUNDevice,
			MergeFile: mergeFile, WebUI: webUI,
		},
		HasRules: d.hasUserConfig(), RulesActive: d.rulesActive, PendingRestart: d.pendingRestart,
		Rules: counts, Warnings: d.warnings, Events: slices.Clone(d.events),
	}
	if gui.ScopeFrom(r.Context()) == gui.ScopeFull && d.fullToken != "" {
		st.WebUIURL = "http://127.0.0.1:" + strconv.Itoa(d.o.GUIPort) + "/?token=" + d.fullToken
	}
	writeJSON(w, st)
}

func (d *Daemon) handleVergeRestart(w http.ResponseWriter, r *http.Request) {
	if gui.ScopeFrom(r.Context()) != gui.ScopeFull {
		httpError(w, http.StatusForbidden, ErrAgentForbidden.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if err := d.RestartVerge(ctx); err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	d.handleStatus(w, r)
}

// handleVergeMode switches the core's mode (rule, global, direct).
func (d *Daemon) handleVergeMode(w http.ResponseWriter, r *http.Request) {
	if gui.ScopeFrom(r.Context()) != gui.ScopeFull {
		httpError(w, http.StatusForbidden, ErrAgentForbidden.Error())
		return
	}
	var body struct {
		Mode string `json:"mode"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := d.SetMode(r.Context(), body.Mode); err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	d.handleStatus(w, r)
}

// handleVergeApply pushes the saved rules into the running core again,
// for when Verge rebuilt its config without them.
func (d *Daemon) handleVergeApply(w http.ResponseWriter, r *http.Request) {
	if gui.ScopeFrom(r.Context()) != gui.ScopeFull {
		httpError(w, http.StatusForbidden, ErrAgentForbidden.Error())
		return
	}
	if err := d.ReloadConfig(r.Context()); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	d.handleStatus(w, r)
}

func (d *Daemon) handleConnections(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	writeJSON(w, d.tracker.List(r.URL.Query().Get("q"), limit))
}

// ConnectionDetail is GET /api/connections/{id}.
type ConnectionDetail struct {
	Conn        Conn        `json:"connection"`
	Explanation Explanation `json:"explanation"`
	Logs        []LogLine   `json:"logs"`
}

func (d *Daemon) handleConnection(w http.ResponseWriter, r *http.Request) {
	c, ok := d.tracker.Get(r.PathValue("id"))
	if !ok {
		httpError(w, http.StatusNotFound, "no such connection (it may have aged out of history)")
		return
	}
	iface := d.defaultInterface(r.Context())
	d.mu.Lock()
	ex := Explain(c, d.ctrlRules, d.sources, iface)
	d.mu.Unlock()
	writeJSON(w, ConnectionDetail{Conn: c, Explanation: ex, Logs: d.tracker.LogsFor(c)})
}

func (d *Daemon) handleProbe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	d.mu.Lock()
	port := d.runtime.MixedPort
	d.mu.Unlock()
	if port == 0 {
		httpError(w, http.StatusConflict, "Clash Verge's mixed port is unknown (its runtime config couldn't be read)")
		return
	}
	res, err := Probe(r.Context(), body.URL, port, d.defaultInterface(r.Context()))
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, res)
}

// CompiledRule is one entry in the final rule list, with its origin.
type CompiledRule struct {
	Position int          `json:"position"`
	Line     string       `json:"line"`
	Source   rules.Source `json:"source"`
}

// RulesView is GET /api/rules.
type RulesView struct {
	Set      rules.Set             `json:"set"`
	Compiled []CompiledRule        `json:"compiled"`
	Packs    map[string]rules.Pack `json:"packs"`
	Types    []string              `json:"types"`
	Active   bool                  `json:"active"` // the core is running these rules
}

func (d *Daemon) handleRules(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v := RulesView{Set: d.ruleSet, Packs: d.ruleSet.AllPacks(), Types: rules.Types, Active: d.rulesActive}
	for i, cr := range d.ctrlRules {
		c := CompiledRule{Position: i + 1, Line: ruleLine(cr)}
		if i < len(d.sources) {
			c.Source = d.sources[i]
		}
		v.Compiled = append(v.Compiled, c)
	}
	writeJSON(w, v)
}

// handleRuleChange applies a change right away. Only a person (full
// scope) can do this; agents must go through proposals.
func (d *Daemon) handleRuleChange(w http.ResponseWriter, r *http.Request) {
	if gui.ScopeFrom(r.Context()) != gui.ScopeFull {
		httpError(w, http.StatusForbidden, ErrAgentForbidden.Error())
		return
	}
	var c rules.Change
	if !readJSON(w, r, &c) {
		return
	}
	if err := d.ApplyChange(r.Context(), c); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	d.handleRules(w, r)
}

// handleRulesPreview dry-runs a change and returns its diff.
func (d *Daemon) handleRulesPreview(w http.ResponseWriter, r *http.Request) {
	var c rules.Change
	if !readJSON(w, r, &c) {
		return
	}
	d.mu.Lock()
	diff, err := d.ruleSet.Diff(c)
	d.mu.Unlock()
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]string{"diff": diff})
}

func (d *Daemon) handleProposals(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, d.proposals.List())
}

func (d *Daemon) handlePropose(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Summary string       `json:"summary"`
		Change  rules.Change `json:"change"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	origin := "user"
	if gui.ScopeFrom(r.Context()) == gui.ScopeAgent {
		origin = "agent"
	}
	p, err := d.Propose(origin, strings.TrimSpace(body.Summary), body.Change)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, p)
}

func (d *Daemon) handleDecide(w http.ResponseWriter, r *http.Request) {
	if gui.ScopeFrom(r.Context()) != gui.ScopeFull {
		httpError(w, http.StatusForbidden, ErrAgentForbidden.Error())
		return
	}
	var accept bool
	switch r.PathValue("decision") {
	case "apply":
		accept = true
	case "reject":
	default:
		httpError(w, http.StatusNotFound, "decision must be apply or reject")
		return
	}
	p, err := d.Decide(r.Context(), r.PathValue("id"), accept)
	if err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, p)
}

func (d *Daemon) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	ifs, err := Interfaces(r.Context(), netstate.ExecRunner{}, d.tunDevice())
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, ifs)
}

// Node is a proxy or group as the GUI shows it.
type Node struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Now     string   `json:"now,omitempty"`
	Members []string `json:"members,omitempty"`
	Alive   bool     `json:"alive"`
	DelayMs int      `json:"delay_ms,omitempty"`
	Health  string   `json:"health,omitempty"` // from the health monitor, if it has checked this node
}

func (d *Daemon) handleNodes(w http.ResponseWriter, r *http.Request) {
	ps, err := d.ctrl.proxies(r.Context())
	if err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	var out []Node
	for _, p := range ps {
		n := Node{Name: p.Name, Type: p.Type, Now: p.Now, Members: p.All, Alive: p.Alive}
		if len(p.History) > 0 {
			n.DelayMs = p.History[len(p.History)-1].Delay
		}
		if sum := d.health.Summary(p.Name); sum.State != health.StateUnknown {
			n.Health = string(sum.State)
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, out)
}

// App is an installed application, for the per-app rule picker.
type App struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

func (d *Daemon) handleApps(w http.ResponseWriter, r *http.Request) {
	home, _ := os.UserHomeDir()
	var apps []App
	for _, dir := range []string{"/Applications", "/Applications/Utilities", "/System/Applications", filepath.Join(home, "Applications")} {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.app"))
		for _, m := range matches {
			apps = append(apps, App{Name: strings.TrimSuffix(filepath.Base(m), ".app"), Path: m})
		}
	}
	sort.Slice(apps, func(i, j int) bool { return strings.ToLower(apps[i].Name) < strings.ToLower(apps[j].Name) })
	writeJSON(w, apps)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		httpError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return false
	}
	return true
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
