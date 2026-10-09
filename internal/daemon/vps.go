package daemon

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/gui"
	"github.com/nyaaorick/clash-mihomac/internal/instance"
	"github.com/nyaaorick/clash-mihomac/internal/vps"
)

// Setup and management of servers runs entirely through these endpoints,
// and only for the person (full scope): an AI assistant can't reach them.
//
// Nothing runs on a server without a preview first. A preview builds the
// plan and keeps it in memory under an id; running takes only that id, so
// what ran is exactly what was shown. A password lives in memory for the
// length of the preview and the run, and is never written to disk.

const (
	pendingTTL        = 10 * time.Minute
	machineCheckEvery = 5 * time.Minute
)

type vpsState struct {
	store  *vps.Store
	dialer vps.Dialer

	mu      sync.Mutex
	pending map[string]*pendingPlan
	jobs    map[string]*vpsJob
	imports map[string]*pendingImport
}

type pendingPlan struct {
	created   time.Time
	plan      vps.Plan
	target    vps.Target // may hold a password
	hostKey   string     // the fingerprint seen when the preview connected
	machineID string     // for actions on an existing machine
	req       SetupRequest
	kind      string // "setup", or an action: restart, rotate, reboot, upgrade
}

type pendingImport struct {
	created time.Time
	nodes   []vps.Node
}

// vpsJob is a running or finished setup or action.
type vpsJob struct {
	mu      sync.Mutex
	ID      string        `json:"id"`
	Title   string        `json:"title"`
	Started time.Time     `json:"started"`
	Done    bool          `json:"done"`
	Error   string        `json:"error,omitempty"`
	Step    int           `json:"step"`
	Steps   int           `json:"steps"`
	Current string        `json:"current,omitempty"`
	Log     []vps.LogLine `json:"log"`
	Outcome *JobOutcome   `json:"outcome,omitempty"`
	sessLog *vps.SessionLog
}

// JobOutcome is what a finished job reports.
type JobOutcome struct {
	Machine   *vps.Machine `json:"machine,omitempty"`
	Node      string       `json:"node,omitempty"`      // the node imported or updated
	EgressIP  string       `json:"egress_ip,omitempty"` // as the server sees itself
	DNSOK     bool         `json:"dns_ok"`
	LatencyMs int          `json:"latency_ms,omitempty"` // end to end through the new node
	KeyLogin  bool         `json:"key_login"`
	Notes     []string     `json:"notes,omitempty"`
}

func (d *Daemon) initVPS() {
	home, _ := instance.Home()
	d.vps = &vpsState{
		store:   &vps.Store{Dir: home + "/vps"},
		dialer:  vps.SSHDialer{},
		pending: map[string]*pendingPlan{},
		jobs:    map[string]*vpsJob{},
		imports: map[string]*pendingImport{},
	}
}

func randID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (v *vpsState) gc() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for id, p := range v.pending {
		if time.Since(p.created) > pendingTTL {
			delete(v.pending, id)
		}
	}
	for id, p := range v.imports {
		if time.Since(p.created) > pendingTTL {
			delete(v.imports, id)
		}
	}
	// Finished jobs are kept for a while so the GUI can show the result.
	for id, j := range v.jobs {
		j.mu.Lock()
		old := j.Done && time.Since(j.Started) > time.Hour
		j.mu.Unlock()
		if old {
			delete(v.jobs, id)
		}
	}
}

// requireFull rejects agents and anything that isn't a person.
func requireFull(w http.ResponseWriter, r *http.Request) bool {
	if gui.ScopeFrom(r.Context()) != gui.ScopeFull {
		httpError(w, http.StatusForbidden, ErrAgentForbidden.Error())
		return false
	}
	return true
}

// ---- setup ----

// SetupRequest describes a server to set up.
type SetupRequest struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`      // SSH port, default 22
	User     string `json:"user"`      // default root
	Password string `json:"password"`  // held in memory only
	NodePort int    `json:"node_port"` // the proxy's port, default 443
	SNI      string `json:"sni"`
	SHA256   string `json:"sha256"`
	Mode     string `json:"mode"` // empty: choose from what the server has
	Region   string `json:"region"`
}

// PlanPreview is what a preview returns.
type PlanPreview struct {
	PlanID        string     `json:"plan_id"`
	HostKey       string     `json:"host_key"` // confirm this fingerprint before running
	Report        vps.Report `json:"report"`
	Mode          string     `json:"mode"`
	SuggestedMode string     `json:"suggested_mode,omitempty"`
	Blocked       []string   `json:"blocked"`
	Text          string     `json:"text"`  // the plan as the person reviews it
	Steps         []PlanStep `json:"steps"` // the same, structured
}

// PlanStep is one previewed step, redacted.
type PlanStep struct {
	Title string `json:"title"`
	Why   string `json:"why"`
	Cmd   string `json:"cmd"`
	File  string `json:"file,omitempty"`
	Body  string `json:"body,omitempty"`
}

func previewOf(id string, p vps.Plan, hostKey string, rep vps.Report) PlanPreview {
	red := p.Redactor()
	out := PlanPreview{PlanID: id, HostKey: hostKey, Report: rep, Mode: p.Mode, Blocked: p.Blocked, Text: p.Render(), Steps: []PlanStep{}}
	if out.Blocked == nil {
		out.Blocked = []string{}
	}
	for _, s := range p.Steps {
		ps := PlanStep{Title: s.Title, Why: s.Why, Cmd: red.Redact(s.Cmd), File: s.File}
		if s.File != "" {
			ps.Body = red.Redact(string(s.Stdin))
		}
		out.Steps = append(out.Steps, ps)
	}
	return out
}

func (d *Daemon) handleVPSPreflight(w http.ResponseWriter, r *http.Request) {
	if !requireFull(w, r) {
		return
	}
	var req SetupRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if req.NodePort == 0 {
		req.NodePort = 443
	}
	if req.User == "" {
		req.User = "root"
	}
	if req.Password == "" {
		httpError(w, http.StatusBadRequest, "enter the server's root password (it is used for this setup only and never stored)")
		return
	}
	target := vps.Target{Host: req.Host, Port: req.Port, User: req.User, Password: req.Password}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	conn, err := d.vps.dialer.Dial(ctx, target)
	if err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer conn.Close()

	report, err := vps.Preflight(ctx, conn, req.NodePort)
	if err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	suggested := vps.ChooseMode(report)
	mode := req.Mode
	if mode == "" {
		mode = suggested
	}
	opts := vps.Options{Mode: mode, Name: firstNonEmpty(req.Name, "node-"+req.Host), Host: req.Host, Port: req.NodePort, SNI: req.SNI, SHA256: req.SHA256, Report: report}
	if mode == vps.ModeRepair || mode == vps.ModeUpgrade {
		_, sni, creds, _, err := vps.ReadExisting(ctx, conn, req.Host, opts.Name)
		if err == nil {
			opts.Creds = creds
			if opts.SNI == "" {
				opts.SNI = sni
			}
		}
	}
	plan, err := vps.BuildPlan(opts)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	d.vps.gc()
	id := randID()
	d.vps.mu.Lock()
	d.vps.pending[id] = &pendingPlan{created: time.Now(), plan: plan, target: target, hostKey: conn.HostKey(), req: req, kind: "setup"}
	d.vps.mu.Unlock()
	prev := previewOf(id, plan, conn.HostKey(), report)
	prev.SuggestedMode = suggested
	writeJSON(w, prev)
}

type runRequest struct {
	PlanID  string `json:"plan_id"`
	HostKey string `json:"host_key"` // the fingerprint the person confirmed (setup only)
}

func (d *Daemon) takePending(id string) (*pendingPlan, error) {
	d.vps.mu.Lock()
	defer d.vps.mu.Unlock()
	p, ok := d.vps.pending[id]
	if !ok || time.Since(p.created) > pendingTTL {
		delete(d.vps.pending, id)
		return nil, errors.New("this preview has expired; preview again")
	}
	delete(d.vps.pending, id) // a plan runs once
	return p, nil
}

func (d *Daemon) handleVPSSetup(w http.ResponseWriter, r *http.Request) {
	if !requireFull(w, r) {
		return
	}
	var req runRequest
	if !readJSON(w, r, &req) {
		return
	}
	p, err := d.takePending(req.PlanID)
	if err != nil {
		httpError(w, http.StatusGone, err.Error())
		return
	}
	if p.kind != "setup" {
		httpError(w, http.StatusBadRequest, "that preview is not a server setup")
		return
	}
	if req.HostKey != p.hostKey || p.hostKey == "" {
		httpError(w, http.StatusConflict, "confirm the server's SSH fingerprint ("+p.hostKey+") before setup runs")
		return
	}
	if len(p.plan.Blocked) > 0 {
		httpError(w, http.StatusConflict, "the plan is blocked: "+strings.Join(p.plan.Blocked, "; "))
		return
	}
	job := d.newJob("Set up " + p.req.Host)
	go d.runSetup(job, p)
	writeJSON(w, map[string]string{"job_id": job.ID})
}

func (d *Daemon) newJob(title string) *vpsJob {
	j := &vpsJob{ID: randID(), Title: title, Started: time.Now(), Log: []vps.LogLine{}}
	d.vps.mu.Lock()
	d.vps.jobs[j.ID] = j
	d.vps.mu.Unlock()
	return j
}

func (j *vpsJob) snapshot() *vpsJob {
	j.mu.Lock()
	defer j.mu.Unlock()
	cp := &vpsJob{ID: j.ID, Title: j.Title, Started: j.Started, Done: j.Done, Error: j.Error, Step: j.Step, Steps: j.Steps, Current: j.Current, Outcome: j.Outcome}
	if j.sessLog != nil {
		cp.Log = j.sessLog.Lines()
	} else {
		cp.Log = []vps.LogLine{}
	}
	return cp
}

func (j *vpsJob) progress(done, total int, title string) {
	j.mu.Lock()
	j.Step, j.Steps, j.Current = done, total, title
	j.mu.Unlock()
}

func (j *vpsJob) finish(out *JobOutcome, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Done, j.Outcome = true, out
	if err != nil {
		j.Error = err.Error()
	}
}

func (d *Daemon) handleVPSJob(w http.ResponseWriter, r *http.Request) {
	if !requireFull(w, r) {
		return
	}
	d.vps.mu.Lock()
	j, ok := d.vps.jobs[r.PathValue("id")]
	d.vps.mu.Unlock()
	if !ok {
		httpError(w, http.StatusNotFound, "no such job")
		return
	}
	writeJSON(w, j.snapshot())
}

// runSetup executes a setup plan, then records the machine, imports its
// node, moves the machine to key login, and checks the node end to end.
func (d *Daemon) runSetup(job *vpsJob, p *pendingPlan) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	home, _ := instance.Home()
	logPath := fmt.Sprintf("%s/vps/logs/%s-%s.log", home, safeFile(p.req.Host), time.Now().Format("20060102-150405"))
	log, err := vps.NewSessionLog(p.plan.Redactor(p.target.Password), logPath)
	if err != nil {
		job.finish(nil, err)
		return
	}
	defer log.Close()
	job.mu.Lock()
	job.sessLog = log
	job.mu.Unlock()
	target := p.target
	target.HostKey = p.hostKey
	defer func() { p.target.Password, target.Password = "", "" }()

	conn, err := d.vps.dialer.Dial(ctx, target)
	if err != nil {
		log.Add("✗ " + err.Error())
		job.finish(nil, err)
		return
	}
	defer conn.Close()
	if err := vps.Execute(ctx, conn, p.plan, log, job.progress); err != nil {
		job.finish(nil, err)
		return
	}
	finished := vps.Finish(ctx, conn, p.plan, log)
	out := &JobOutcome{EgressIP: finished.EgressIP, DNSOK: finished.DNSOK}

	name := p.plan.Options.Name
	m, err := d.vps.store.Add(vps.Machine{
		Name: firstNonEmpty(p.req.Name, name), Host: p.req.Host, Port: p.req.Port, User: p.req.User, HostKey: p.hostKey,
		Region: p.req.Region, NodeName: name, NodePort: p.plan.Options.Port,
	})
	if err != nil {
		// Re-running setup on a server that is already managed: find it.
		if existing, gerr := d.machineByHost(p.req.Host, p.req.Port); gerr == nil {
			m, err = existing, nil
			d.vps.store.Update(m.ID, func(x *vps.Machine) { x.NodeName, x.NodePort = name, p.plan.Options.Port })
		}
	}
	if err != nil {
		log.Add("✗ couldn't save the machine: " + err.Error())
		job.finish(out, err)
		return
	}
	out.Machine = &m

	if node, err := d.importLink(ctx, finished.Link, m.ID, log); err != nil {
		out.Notes = append(out.Notes, "the node couldn't be imported automatically: "+err.Error())
	} else {
		out.Node = node
		if ms, err := d.measureNode(ctx, node); err == nil {
			out.LatencyMs = ms
			log.Add(fmt.Sprintf("✓ connected through %s: %d ms end to end", node, ms))
		} else {
			out.Notes = append(out.Notes, "the node was imported but the end-to-end test through it failed: "+err.Error())
			log.Add("✗ end-to-end test through the node failed: " + err.Error())
		}
	}

	if err := d.switchToKeyLogin(ctx, conn, &m, log); err != nil {
		out.Notes = append(out.Notes, "key login wasn't set up: "+err.Error())
	} else {
		out.KeyLogin = true
		out.Notes = append(out.Notes, "Key login is on. You can now turn off password login for this server from its card.")
	}
	if fresh, err := d.vps.store.Get(m.ID); err == nil {
		out.Machine = &fresh
	}
	job.finish(out, nil)
}

func safeFile(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func (d *Daemon) machineByHost(host string, port int) (vps.Machine, error) {
	ms, err := d.vps.store.List()
	if err != nil {
		return vps.Machine{}, err
	}
	for _, m := range ms {
		if m.Host == host && m.Port == port {
			return m, nil
		}
	}
	return vps.Machine{}, errors.New("not found")
}

// importLink parses a share link, adds it to the imported nodes (replacing
// the same machine's earlier node), and reloads the running config. It
// returns the node's name.
func (d *Daemon) importLink(ctx context.Context, link, machineID string, log *vps.SessionLog) (string, error) {
	n, err := vps.ParseLink(link)
	if err != nil {
		return "", err
	}
	names, err := d.addNodes([]vps.Node{n}, machineID)
	if err != nil {
		return "", err
	}
	if log != nil {
		log.Add("imported node " + names[0])
	}
	return names[0], d.ReloadConfig(ctx)
}

// addNodes saves nodes as imported, without reloading.
func (d *Daemon) addNodes(nodes []vps.Node, machineID string) ([]string, error) {
	path := d.inst.Path("nodes.yaml")
	list, err := vps.LoadNodes(path)
	if err != nil {
		return nil, err
	}
	taken := map[string]bool{}
	if ts, err := userNodeNames(d.o.ConfigPath); err == nil {
		taken = ts
	}
	var add []vps.Imported
	for _, n := range nodes {
		add = append(add, vps.Imported{Node: n, Machine: machineID, Added: time.Now()})
	}
	merged, err := vps.MergeNodes(list, add, taken)
	if err != nil {
		return nil, err
	}
	if err := vps.SaveNodes(path, merged); err != nil {
		return nil, err
	}
	var names []string
	for _, a := range add {
		names = append(names, a.Name)
	}
	// MergeNodes may have renamed clashes; report the saved names.
	names = names[:0]
	for _, m := range merged[len(merged)-len(add):] {
		names = append(names, m.Name)
	}
	if machineID != "" && len(add) == 1 { // a replaced node keeps its slot
		for _, m := range merged {
			if m.Machine == machineID && m.Name == add[0].Name {
				names = []string{m.Name}
			}
		}
	}
	return names, nil
}

// measureNode runs mihomo's delay test through a node.
func (d *Daemon) measureNode(ctx context.Context, node string) (int, error) {
	var last error
	for i := 0; i < 3; i++ { // the core may still be loading the new config
		dur, err := d.ctrl.delay(ctx, node, "https://www.gstatic.com/generate_204", 6*time.Second)
		if err == nil {
			return int(dur / time.Millisecond), nil
		}
		last = err
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return 0, last
}

// switchToKeyLogin generates a key, authorizes it on the server, proves it
// works on a fresh connection, and only then stores it. The password is
// never needed again.
func (d *Daemon) switchToKeyLogin(ctx context.Context, conn vps.Conn, m *vps.Machine, log *vps.SessionLog) error {
	priv, pub, err := vps.GenerateKey("clash-mihomac-" + m.Name)
	if err != nil {
		return err
	}
	log.Redactor().Add(string(priv))
	if err := vps.InstallKey(ctx, conn, pub); err != nil {
		return err
	}
	t := vps.Target{Host: m.Host, Port: m.Port, User: m.User, KeyPEM: priv, HostKey: m.HostKey}
	test, err := d.vps.dialer.Dial(ctx, t)
	if err != nil {
		return fmt.Errorf("the new key was installed but logging in with it failed: %w", err)
	}
	test.Close()
	if err := d.vps.store.SaveKey(m.ID, priv); err != nil {
		return err
	}
	log.Add("✓ key login verified on a fresh connection; the password is no longer needed")
	return nil
}

func userNodeNames(configPath string) (map[string]bool, error) {
	targets, err := (&Daemon{o: Options{ConfigPath: configPath}}).userTargets()
	if err != nil {
		return nil, err
	}
	m := map[string]bool{}
	for _, t := range targets {
		m[t.Name] = true
	}
	return m, nil
}

// ---- machines ----

// MachineView is a machine with its latest health, for the GUI.
type MachineView struct {
	vps.Machine
	TrafficUsedGB float64 `json:"traffic_used_gb"`
	QuotaPercent  float64 `json:"quota_percent,omitempty"`
}

func machineView(m vps.Machine) MachineView {
	v := MachineView{Machine: m, TrafficUsedGB: float64(m.Traffic.Bytes) / (1 << 30)}
	if m.Quota.GB > 0 {
		v.QuotaPercent = 100 * v.TrafficUsedGB / float64(m.Quota.GB)
	}
	return v
}

func (d *Daemon) handleVPSMachines(w http.ResponseWriter, r *http.Request) {
	if !requireFull(w, r) {
		return
	}
	ms, err := d.vps.store.List()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]MachineView, 0, len(ms))
	for _, m := range ms {
		out = append(out, machineView(m))
	}
	writeJSON(w, out)
}

func (d *Daemon) machineFromPath(w http.ResponseWriter, r *http.Request) (vps.Machine, bool) {
	m, err := d.vps.store.Get(r.PathValue("id"))
	if err != nil {
		httpError(w, http.StatusNotFound, err.Error())
		return vps.Machine{}, false
	}
	return m, true
}

// dialMachine connects with the machine's stored key.
func (d *Daemon) dialMachine(ctx context.Context, m vps.Machine) (vps.Conn, error) {
	if !m.HasKey {
		return nil, errors.New("this server has no stored SSH key (it was added without finishing setup); set it up again to manage it")
	}
	t, err := d.vps.store.Target(m)
	if err != nil {
		return nil, err
	}
	return d.vps.dialer.Dial(ctx, t)
}

// checkMachine reads a machine's health and updates its record.
func (d *Daemon) checkMachine(ctx context.Context, m vps.Machine) vps.Machine {
	now := time.Now()
	chk := &vps.Check{Time: now, State: vps.StateUnreachable}
	conn, err := d.dialMachine(ctx, m)
	if err != nil {
		chk.Error = err.Error()
	} else {
		metrics, merr := vps.Collect(ctx, conn, now)
		conn.Close()
		if merr != nil {
			chk.Error = merr.Error()
		} else {
			chk.Metrics = &metrics
			chk.State, chk.Reasons = vps.Judge(metrics, now)
			m.Traffic = m.Traffic.Account(metrics, m.Quota, now)
		}
	}
	updated, err := d.vps.store.Update(m.ID, func(x *vps.Machine) {
		x.Last = chk
		x.Traffic = m.Traffic
	})
	if err != nil {
		return m
	}
	return updated
}

func (d *Daemon) handleVPSCheck(w http.ResponseWriter, r *http.Request) {
	if !requireFull(w, r) {
		return
	}
	m, ok := d.machineFromPath(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	writeJSON(w, machineView(d.checkMachine(ctx, m)))
}

// monitorMachines checks every machine that has a stored key.
func (d *Daemon) monitorMachines(ctx context.Context) {
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ms, _ := d.vps.store.List()
		sem := make(chan struct{}, 3)
		var wg sync.WaitGroup
		for _, m := range ms {
			if !m.HasKey {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
				defer cancel()
				d.checkMachine(cctx, m)
			}()
		}
		wg.Wait()
		t.Reset(machineCheckEvery)
	}
}

func (d *Daemon) handleVPSQuota(w http.ResponseWriter, r *http.Request) {
	if !requireFull(w, r) {
		return
	}
	m, ok := d.machineFromPath(w, r)
	if !ok {
		return
	}
	var q vps.Quota
	if !readJSON(w, r, &q) {
		return
	}
	if q.GB < 0 || q.GB > 1_000_000 || q.ResetDay < 0 || q.ResetDay > 28 {
		httpError(w, http.StatusBadRequest, "quota must be 0 or more GB, with a reset day from 1 to 28")
		return
	}
	updated, err := d.vps.store.Update(m.ID, func(x *vps.Machine) { x.Quota = q })
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, machineView(updated))
}

// ---- actions ----

type actionRequest struct {
	Kind   string `json:"kind"` // restart, rotate, reboot, upgrade
	SHA256 string `json:"sha256"`
}

func (d *Daemon) handleVPSActionPreview(w http.ResponseWriter, r *http.Request) {
	if !requireFull(w, r) {
		return
	}
	m, ok := d.machineFromPath(w, r)
	if !ok {
		return
	}
	var req actionRequest
	if !readJSON(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	conn, err := d.dialMachine(ctx, m)
	if err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer conn.Close()

	var plan vps.Plan
	var report vps.Report
	switch req.Kind {
	case vps.ActionRestart, vps.ActionReboot:
		plan, err = vps.ActionPlan(req.Kind, m, 0, "")
	case vps.ActionRotate:
		var port int
		var sni string
		if port, sni, _, _, err = vps.ReadExisting(ctx, conn, m.Host, firstNonEmpty(m.NodeName, m.Name)); err == nil {
			plan, err = vps.ActionPlan(req.Kind, m, port, sni)
		}
	case "upgrade":
		report, err = vps.Preflight(ctx, conn, firstNonZero(m.NodePort, 443))
		if err == nil {
			var sni string
			var creds vps.Creds
			_, sni, creds, _, err = vps.ReadExisting(ctx, conn, m.Host, firstNonEmpty(m.NodeName, m.Name))
			if err == nil {
				plan, err = vps.BuildPlan(vps.Options{Mode: vps.ModeUpgrade, Name: firstNonEmpty(m.NodeName, m.Name), Host: m.Host, Port: firstNonZero(m.NodePort, 443),
					SNI: sni, SHA256: req.SHA256, Report: report, Creds: creds})
			}
		}
	default:
		err = fmt.Errorf("unknown action %q", req.Kind)
	}
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	d.vps.gc()
	id := randID()
	t, _ := d.vps.store.Target(m)
	d.vps.mu.Lock()
	d.vps.pending[id] = &pendingPlan{created: time.Now(), plan: plan, target: t, hostKey: m.HostKey, machineID: m.ID, kind: req.Kind}
	d.vps.mu.Unlock()
	writeJSON(w, previewOf(id, plan, m.HostKey, report))
}

func firstNonZero(vs ...int) int {
	for _, v := range vs {
		if v != 0 {
			return v
		}
	}
	return 0
}

func (d *Daemon) handleVPSActionRun(w http.ResponseWriter, r *http.Request) {
	if !requireFull(w, r) {
		return
	}
	m, ok := d.machineFromPath(w, r)
	if !ok {
		return
	}
	var req runRequest
	if !readJSON(w, r, &req) {
		return
	}
	p, err := d.takePending(req.PlanID)
	if err != nil {
		httpError(w, http.StatusGone, err.Error())
		return
	}
	if p.machineID != m.ID || p.kind == "setup" {
		httpError(w, http.StatusBadRequest, "that preview belongs to something else")
		return
	}
	if len(p.plan.Blocked) > 0 {
		httpError(w, http.StatusConflict, "the plan is blocked: "+strings.Join(p.plan.Blocked, "; "))
		return
	}
	job := d.newJob(fmt.Sprintf("%s %s", p.kind, m.Name))
	go d.runAction(job, p, m)
	writeJSON(w, map[string]string{"job_id": job.ID})
}

func (d *Daemon) runAction(job *vpsJob, p *pendingPlan, m vps.Machine) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	home, _ := instance.Home()
	log, err := vps.NewSessionLog(p.plan.Redactor(), fmt.Sprintf("%s/vps/logs/%s-%s-%s.log", home, safeFile(m.Host), p.kind, time.Now().Format("20060102-150405")))
	if err != nil {
		job.finish(nil, err)
		return
	}
	defer log.Close()
	job.mu.Lock()
	job.sessLog = log
	job.mu.Unlock()

	conn, err := d.dialMachine(ctx, m)
	if err != nil {
		log.Add("✗ " + err.Error())
		job.finish(nil, err)
		return
	}
	defer conn.Close()
	err = vps.Execute(ctx, conn, p.plan, log, job.progress)
	out := &JobOutcome{}
	if err != nil && p.kind == vps.ActionReboot {
		err = nil // the connection drops as the server goes down
	}
	if err != nil {
		job.finish(out, err)
		return
	}
	switch p.kind {
	case vps.ActionRotate:
		node, ierr := d.importLink(ctx, p.plan.Link, m.ID, log)
		if ierr != nil {
			out.Notes = append(out.Notes, "the new link couldn't be imported: "+ierr.Error())
		} else {
			out.Node = node
			if ms, merr := d.measureNode(ctx, node); merr == nil {
				out.LatencyMs = ms
			}
			out.Notes = append(out.Notes, "Credentials rotated. Old share links no longer work; the new node is already imported here.")
		}
	case "upgrade":
		out.Notes = append(out.Notes, "Proxy core upgraded; the previous binary is kept on the server as sing-box.prev.")
	case vps.ActionReboot:
		out.Notes = append(out.Notes, "Reboot requested. The server will be unreachable for a minute or so.")
	}
	fresh := d.checkMachine(ctx, m)
	out.Machine = &fresh
	job.finish(out, nil)
}

// ---- password login, removal, sharing ----

func (d *Daemon) handleVPSDisablePassword(w http.ResponseWriter, r *http.Request) {
	if !requireFull(w, r) {
		return
	}
	m, ok := d.machineFromPath(w, r)
	if !ok {
		return
	}
	var body struct {
		Confirm bool `json:"confirm"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !body.Confirm {
		httpError(w, http.StatusBadRequest, "this turns off SSH password login on "+m.Name+" (key login stays); send confirm: true to proceed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	conn, err := d.dialMachine(ctx, m) // proves the key works right now
	if err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer conn.Close()
	if err := vps.DisablePasswordLogin(ctx, conn); err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]string{"result": "password login is off; this Mac's key still works"})
}

func (d *Daemon) handleVPSRemove(w http.ResponseWriter, r *http.Request) {
	if !requireFull(w, r) {
		return
	}
	m, ok := d.machineFromPath(w, r)
	if !ok {
		return
	}
	var body struct {
		Confirm   bool `json:"confirm"`
		Uninstall bool `json:"uninstall"` // also remove the proxy from the server
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !body.Confirm {
		httpError(w, http.StatusBadRequest, "this forgets "+m.Name+" here (and its imported node); send confirm: true to proceed")
		return
	}
	var notes []string
	if body.Uninstall {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		conn, err := d.dialMachine(ctx, m)
		if err != nil {
			httpError(w, http.StatusBadGateway, "couldn't reach the server to uninstall: "+err.Error())
			return
		}
		res, err := conn.Run(ctx, "sh -c "+vpsQuote(uninstallCmd), nil)
		conn.Close()
		if err != nil || !res.OK() {
			httpError(w, http.StatusBadGateway, "the uninstall failed; nothing was forgotten here")
			return
		}
		notes = append(notes, "The proxy was removed from the server.")
	}
	// Forget the node and the machine.
	if nodes, err := vps.LoadNodes(d.inst.Path("nodes.yaml")); err == nil {
		keep := nodes[:0]
		for _, n := range nodes {
			if n.Machine != m.ID {
				keep = append(keep, n)
			}
		}
		vps.SaveNodes(d.inst.Path("nodes.yaml"), keep)
	}
	if err := d.vps.store.Remove(m.ID); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := d.ReloadConfig(r.Context()); err != nil {
		notes = append(notes, "the running config couldn't be reloaded: "+err.Error())
	}
	writeJSON(w, map[string]any{"removed": m.Name, "notes": notes})
}

const uninstallCmd = "systemctl disable --now sing-box 2>/dev/null; rm -f /etc/systemd/system/sing-box.service /usr/local/bin/sing-box /usr/local/bin/sing-box.prev /etc/sysctl.d/99-mihomac-bbr.conf; rm -rf /etc/sing-box; systemctl daemon-reload"

func vpsQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// ShareView is a node's share material. It contains the node's credentials.
type ShareView struct {
	Link         string `json:"link"`
	Subscription string `json:"subscription"` // base64 of the link, for subscription-style clients
	QRPNG        string `json:"qr_png"`       // base64 PNG
}

func (d *Daemon) handleVPSShare(w http.ResponseWriter, r *http.Request) {
	if !requireFull(w, r) {
		return
	}
	m, ok := d.machineFromPath(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	conn, err := d.dialMachine(ctx, m)
	if err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer conn.Close()
	_, _, _, link, err := vps.ReadExisting(ctx, conn, m.Host, firstNonEmpty(m.NodeName, m.Name))
	if err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	png, err := vps.QRPNG(link, 320)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, ShareView{Link: link, Subscription: vps.Subscription(link), QRPNG: base64.StdEncoding.EncodeToString(png)})
}

// ---- import ----

// ImportPreview lists what an import found, without credentials.
type ImportPreview struct {
	ImportID string       `json:"import_id"`
	Nodes    []ImportNode `json:"nodes"`
	Errors   []string     `json:"errors"`
}

// ImportNode is a node as the import preview shows it.
type ImportNode struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Insecure bool   `json:"insecure,omitempty"` // certificate verification is turned off
}

func (d *Daemon) handleVPSImport(w http.ResponseWriter, r *http.Request) {
	if !requireFull(w, r) {
		return
	}
	var req struct {
		Text  string `json:"text"`  // one link, several, or a subscription body
		Image string `json:"image"` // a QR code image as a data URL
	}
	if !readJSON(w, r, &req) {
		return
	}
	text := req.Text
	if req.Image != "" {
		raw, err := vps.DataURLBytes(req.Image)
		if err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		if text, err = vps.DecodeQR(raw); err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if strings.TrimSpace(text) == "" {
		httpError(w, http.StatusBadRequest, "paste a share link, a subscription, or upload a QR code image")
		return
	}
	nodes, errs := vps.ParseSubscription([]byte(text))
	prev := ImportPreview{Nodes: []ImportNode{}, Errors: []string{}}
	for _, e := range errs {
		prev.Errors = append(prev.Errors, e.Error())
	}
	for _, n := range nodes {
		insecure, _ := n.Proxy["skip-cert-verify"].(bool)
		prev.Nodes = append(prev.Nodes, ImportNode{Name: n.Name, Type: n.Type, Server: n.Server, Port: n.Port, Insecure: insecure})
	}
	if len(nodes) > 0 {
		d.vps.gc()
		prev.ImportID = randID()
		d.vps.mu.Lock()
		d.vps.imports[prev.ImportID] = &pendingImport{created: time.Now(), nodes: nodes}
		d.vps.mu.Unlock()
	}
	writeJSON(w, prev)
}

func (d *Daemon) handleVPSImportApply(w http.ResponseWriter, r *http.Request) {
	if !requireFull(w, r) {
		return
	}
	var req struct {
		ImportID string   `json:"import_id"`
		Names    []string `json:"names"` // import only these; empty means all
	}
	if !readJSON(w, r, &req) {
		return
	}
	d.vps.mu.Lock()
	p, ok := d.vps.imports[req.ImportID]
	delete(d.vps.imports, req.ImportID)
	d.vps.mu.Unlock()
	if !ok || time.Since(p.created) > pendingTTL {
		httpError(w, http.StatusGone, "this import has expired; paste the links again")
		return
	}
	var pick []vps.Node
	for _, n := range p.nodes {
		if len(req.Names) == 0 || contains(req.Names, n.Name) {
			pick = append(pick, n)
		}
	}
	if len(pick) == 0 {
		httpError(w, http.StatusBadRequest, "no nodes selected")
		return
	}
	names, err := d.addNodes(pick, "")
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := map[string]any{"imported": names}
	if err := d.ReloadConfig(r.Context()); err != nil {
		resp["warning"] = "saved, but the running config couldn't be reloaded: " + err.Error()
	}
	writeJSON(w, resp)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
