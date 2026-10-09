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
	"github.com/nyaaorick/clash-mihomac/internal/helper"
	"github.com/nyaaorick/clash-mihomac/internal/netstate"
	"github.com/nyaaorick/clash-mihomac/internal/rules"
	"github.com/nyaaorick/clash-mihomac/internal/runtimecfg"
)

// api returns the /api/ handlers. Authentication and scopes are enforced
// by the gui package before these run.
func (d *Daemon) api() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", d.handleStatus)
	mux.HandleFunc("POST /api/mode", d.handleMode)
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
	mux.HandleFunc("GET /api/instances", d.handleInstances)
	mux.HandleFunc("GET /api/logs", d.handleLogs)
	return mux
}

// Status is GET /api/status.
type Status struct {
	Instance      string         `json:"instance"`
	Channel       string         `json:"channel"`
	Mode          string         `json:"mode"`
	Modes         []string       `json:"modes"`
	MixedPort     int            `json:"mixed_port"`
	TUNDevice     string         `json:"tun_device"`
	CoreVersion   string         `json:"core_version"`
	MihomoVersion string         `json:"mihomo_version"`
	ConfigPath    string         `json:"config_path"`
	StartedAt     time.Time      `json:"started_at"`
	Helper        HelperStatus   `json:"helper"`
	Rules         map[string]int `json:"rules"`
	Warnings      []string       `json:"warnings"`
	Events        []Event        `json:"events"`
}

// HelperStatus says whether the privileged helper is reachable.
type HelperStatus struct {
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	v, _ := d.ctrl.version(ctx)
	var hs HelperStatus
	var ping map[string]string
	if err := helper.Call(ctx, d.o.HelperSocket, "ping", nil, &ping); err != nil {
		hs.Error = err.Error()
	} else {
		hs.Available, hs.Version = true, ping["version"]
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	counts := map[string]int{}
	for _, s := range d.sources {
		counts[s.Kind]++
	}
	writeJSON(w, Status{
		Instance: d.inst.Name, Channel: d.o.Channel, Mode: d.mode, Modes: runtimecfg.Modes,
		MixedPort: d.inst.MixedPort, TUNDevice: d.inst.TUNDevice,
		CoreVersion: d.o.CoreVersion, MihomoVersion: v, ConfigPath: d.o.ConfigPath, StartedAt: d.startedAt,
		Helper: hs, Rules: counts, Warnings: d.warnings, Events: slices.Clone(d.events),
	})
}

func (d *Daemon) handleMode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !slices.Contains(runtimecfg.Modes, body.Mode) {
		httpError(w, http.StatusBadRequest, "unknown mode "+strconv.Quote(body.Mode))
		return
	}
	if err := d.SetMode(r.Context(), body.Mode); err != nil {
		httpError(w, http.StatusConflict, err.Error())
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
	res, err := Probe(r.Context(), body.URL, d.inst.MixedPort, d.defaultInterface(r.Context()))
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
}

func (d *Daemon) handleRules(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v := RulesView{Set: d.ruleSet, Packs: d.ruleSet.AllPacks(), Types: rules.Types}
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
	d.mu.Lock()
	next, err := d.ruleSet.Apply(c)
	d.mu.Unlock()
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := d.ApplyRules(r.Context(), next); err != nil {
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
	ifs, err := Interfaces(r.Context(), netstate.ExecRunner{}, d.inst.TUNDevice)
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
