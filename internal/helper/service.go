package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/nyaaorick/clash-mihomac/internal/core"
	"github.com/nyaaorick/clash-mihomac/internal/instance"
	"github.com/nyaaorick/clash-mihomac/internal/netstate"
	"github.com/nyaaorick/clash-mihomac/internal/runtimecfg"
)

// Route recovery gives up after this many core restarts in the window.
const (
	maxRestarts   = 3
	restartWindow = 10 * time.Minute
)

// DefaultRoot is where the installed helper keeps its state.
const DefaultRoot = "/Library/Application Support/Mihomac/helper"

// Session kinds.
const (
	KindTUN      = "tun"
	KindSysProxy = "sysproxy"
)

// Service is the helper's state: active sessions and the network backup.
//
// A session is either a TUN core running as root or the system proxy
// pointing at an instance. The first session to change the system takes a
// network backup; when the last session ends, the backup is restored,
// verified, and deleted. A backup that survives a crash or reboot is
// restored by Recover when the helper next starts.
type Service struct {
	Root    string
	UID     int // the allowed user; handed-over files are chowned to it
	Version string
	Log     *log.Logger
	Poll    time.Duration

	// Swappable for tests.
	Runner netstate.Runner
	Verify func(path string) (string, error)
	Exec   func(bin string, args []string, logf *os.File) (*exec.Cmd, error)
	Alive  func(pid int) bool
	IsCore func(pid int) bool

	mu        sync.Mutex
	sessions  map[string]*session
	events    []Event
	lastTick  time.Time
	ticks     int
	lastIface string
	missing   map[string]int
}

type session struct {
	Instance  string    `json:"instance"`
	Kind      string    `json:"kind"`
	ClientPID int       `json:"client_pid"`
	CorePID   int       `json:"core_pid,omitempty"`
	Device    string    `json:"device,omitempty"`
	Gateway   string    `json:"gateway,omitempty"`
	Started   time.Time `json:"started"`

	dir        string
	controller string
	restarts   []time.Time
	cmd        *exec.Cmd
	exited     chan struct{}
}

// Event is a notable thing the helper did, kept for `status`.
type Event struct {
	Time     time.Time        `json:"time"`
	Instance string           `json:"instance,omitempty"`
	Message  string           `json:"message"`
	Network  *netstate.Report `json:"network,omitempty"`
}

// NewService returns a Service using the real system.
func NewService(root string, uid int, version string, logger *log.Logger) *Service {
	return &Service{
		Root: root, UID: uid, Version: version, Log: logger, Poll: time.Second,
		Runner: netstate.ExecRunner{},
		Verify: core.VerifyBinary,
		Exec:   execCore,
		Alive:  alive,
		IsCore: func(pid int) bool { return procName(pid) == "mihomo" },
	}
}

func (s *Service) init() {
	if s.sessions == nil {
		s.sessions = map[string]*session{}
		s.missing = map[string]int{}
	}
	if s.Log == nil {
		s.Log = log.New(io.Discard, "", 0)
	}
}

// Commands returns the helper's full command allowlist.
func (s *Service) Commands() map[string]Command {
	s.mu.Lock()
	s.init()
	s.mu.Unlock()
	return map[string]Command{
		"ping": func(context.Context, Peer, json.RawMessage) (any, error) {
			return map[string]string{"version": s.Version}, nil
		},
		"network-snapshot": func(ctx context.Context, _ Peer, _ json.RawMessage) (any, error) {
			return netstate.Take(ctx, s.Runner)
		},
		"status":          s.status,
		"sockets":         s.sockets,
		"tun-start":       s.tunStart,
		"tun-reload":      s.tunReload,
		"tun-stop":        s.stopCmd(KindTUN),
		"sysproxy-set":    s.sysproxySet,
		"sysproxy-clear":  s.stopCmd(KindSysProxy),
		"restore-network": s.restoreAll,
	}
}

// TUNStartArgs are the arguments to tun-start. The mihomo binary itself
// is passed as an open file alongside the request.
type TUNStartArgs struct {
	Instance string `json:"instance"`
	Config   string `json:"config"`
}

// TUNStartResult is tun-start's reply.
type TUNStartResult struct {
	CorePID  int      `json:"core_pid"`
	Version  string   `json:"version"`
	LogPath  string   `json:"log_path"`
	Warnings []string `json:"warnings,omitempty"`
}

func (s *Service) tunStart(ctx context.Context, peer Peer, raw json.RawMessage) (any, error) {
	var a TUNStartArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	inst, err := instance.Get("", a.Instance)
	if err != nil {
		return nil, err
	}
	if peer.PID <= 0 {
		return nil, errors.New("cannot identify the calling process")
	}
	if len(peer.Files) != 1 {
		return nil, errors.New("tun-start needs the mihomo binary passed as an open file")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	if cur, ok := s.sessions[inst.Name]; ok {
		return nil, fmt.Errorf("instance %s already has a %s session", inst.Name, cur.Kind)
	}

	dir := filepath.Join(s.Root, "run", inst.Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	// Copy the core somewhere only root can write, then verify the copy,
	// so the binary can't be swapped between the check and the exec.
	bin := filepath.Join(dir, "mihomo")
	if err := copyFile(peer.Files[0], bin+".tmp", 0o755); err != nil {
		return nil, fmt.Errorf("copy core: %w", err)
	}
	version, err := s.Verify(bin + ".tmp")
	if err != nil {
		os.Remove(bin + ".tmp")
		return nil, err
	}
	if err := os.Rename(bin+".tmp", bin); err != nil {
		return nil, err
	}

	cfgPath, warnings, err := s.writeConfig(inst, dir, a.Config)
	if err != nil {
		return nil, err
	}
	if err := s.ensureBackup(ctx); err != nil {
		return nil, fmt.Errorf("back up network settings: %w", err)
	}
	s.removeLeftoverRoutes(ctx, inst.TUNDevice, inst.TUNGateway())

	sess := &session{
		Instance: inst.Name, Kind: KindTUN, ClientPID: peer.PID, Device: inst.TUNDevice, Gateway: inst.TUNGateway(),
		Started: time.Now(), dir: dir, controller: fmt.Sprintf("127.0.0.1:%d", inst.ControllerPort),
	}
	if err := s.startCore(sess, bin, cfgPath); err != nil {
		s.finishIfIdle(ctx)
		return nil, err
	}
	s.sessions[inst.Name] = sess
	s.event(inst.Name, fmt.Sprintf("TUN started on %s (mihomo %s, pid %d) for client pid %d", inst.TUNDevice, version, sess.CorePID, peer.PID), nil)
	return TUNStartResult{CorePID: sess.CorePID, Version: version, LogPath: filepath.Join(dir, "mihomo.log"), Warnings: warnings}, nil
}

// writeConfig re-applies Clash Mihomac's enforcement to a client-supplied
// config and writes it where the root core reads it.
func (s *Service) writeConfig(inst instance.Instance, dir, config string) (string, []string, error) {
	var meta struct {
		Secret string `yaml:"secret"`
	}
	if err := yaml.Unmarshal([]byte(config), &meta); err != nil {
		return "", nil, fmt.Errorf("parse config: %w", err)
	}
	if len(meta.Secret) < 16 {
		return "", nil, errors.New("config must carry a controller secret of at least 16 characters")
	}
	res, err := runtimecfg.Build([]byte(config), runtimecfg.Options{
		MixedPort: inst.MixedPort, ControllerPort: inst.ControllerPort, Secret: meta.Secret,
		Mode: runtimecfg.ModeTUN, TUNDevice: inst.TUNDevice, TUNAddress: inst.TUNAddress,
	})
	if err != nil {
		return "", nil, err
	}
	path := filepath.Join(dir, "runtime.yaml")
	if err := os.WriteFile(path, res.Config, 0o600); err != nil {
		return "", nil, err
	}
	return path, res.Warnings, nil
}

func (s *Service) startCore(sess *session, bin, cfgPath string) error {
	logPath := filepath.Join(sess.dir, "mihomo.log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer logf.Close()
	s.handOver(logPath)
	cmd, err := s.Exec(bin, []string{"-d", sess.dir, "-f", cfgPath}, logf)
	if err != nil {
		return fmt.Errorf("start mihomo: %w", err)
	}
	sess.cmd = cmd
	sess.CorePID = cmd.Process.Pid
	sess.exited = make(chan struct{})
	go func(done chan struct{}) {
		cmd.Wait()
		close(done)
	}(sess.exited)
	return os.WriteFile(filepath.Join(sess.dir, "core.pid"), []byte(strconv.Itoa(sess.CorePID)), 0o644)
}

// TUNReloadArgs are the arguments to tun-reload.
type TUNReloadArgs struct {
	Instance string `json:"instance"`
	Config   string `json:"config"`
}

func (s *Service) tunReload(ctx context.Context, _ Peer, raw json.RawMessage) (any, error) {
	var a TUNReloadArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	inst, err := instance.Get("", a.Instance)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	sess, ok := s.sessions[inst.Name]
	if !ok || sess.Kind != KindTUN {
		return nil, fmt.Errorf("instance %s has no TUN session", inst.Name)
	}
	path, warnings, err := s.writeConfig(inst, sess.dir, a.Config)
	if err != nil {
		return nil, err
	}
	var meta struct {
		Secret string `yaml:"secret"`
	}
	yaml.Unmarshal([]byte(a.Config), &meta)
	body, _ := json.Marshal(map[string]string{"path": path})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://"+sess.controller+"/configs?force=true", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+meta.Secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reload core: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("reload core: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	s.event(inst.Name, "TUN config reloaded", nil)
	return map[string]any{"warnings": warnings}, nil
}

// InstanceArgs name an instance.
type InstanceArgs struct {
	Instance string `json:"instance"`
}

func (s *Service) sysproxySet(ctx context.Context, peer Peer, raw json.RawMessage) (any, error) {
	var a InstanceArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	inst, err := instance.Get("", a.Instance)
	if err != nil {
		return nil, err
	}
	if peer.PID <= 0 {
		return nil, errors.New("cannot identify the calling process")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	if cur, ok := s.sessions[inst.Name]; ok {
		return nil, fmt.Errorf("instance %s already has a %s session", inst.Name, cur.Kind)
	}
	if err := s.ensureBackup(ctx); err != nil {
		return nil, fmt.Errorf("back up network settings: %w", err)
	}
	if err := netstate.SetSystemProxy(ctx, s.Runner, inst.MixedPort); err != nil {
		s.finishIfIdle(ctx)
		return nil, err
	}
	s.sessions[inst.Name] = &session{Instance: inst.Name, Kind: KindSysProxy, ClientPID: peer.PID, Started: time.Now()}
	s.event(inst.Name, fmt.Sprintf("system proxy set to 127.0.0.1:%d for client pid %d", inst.MixedPort, peer.PID), nil)
	return map[string]int{"port": inst.MixedPort}, nil
}

func (s *Service) stopCmd(kind string) Command {
	return func(ctx context.Context, _ Peer, raw json.RawMessage) (any, error) {
		var a InstanceArgs
		if err := decodeArgs(raw, &a); err != nil {
			return nil, err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.init()
		sess, ok := s.sessions[a.Instance]
		if !ok || sess.Kind != kind {
			return Event{Instance: a.Instance, Message: "no active " + kind + " session"}, nil
		}
		return s.endSession(ctx, a.Instance, "stopped by client"), nil
	}
}

// RestoreResult is restore-network's reply.
type RestoreResult struct {
	Ended   []Event          `json:"ended"`
	Network *netstate.Report `json:"network,omitempty"`
}

func (s *Service) restoreAll(ctx context.Context, _ Peer, _ json.RawMessage) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	var res RestoreResult
	for _, name := range s.sessionNames() {
		ev := s.endSession(ctx, name, "restore-network requested")
		res.Ended = append(res.Ended, ev)
		if ev.Network != nil {
			res.Network = ev.Network
		}
	}
	s.killLeftoverCores()
	for _, name := range instance.Slots() {
		inst, _ := instance.Get("", name)
		s.removeLeftoverRoutes(ctx, inst.TUNDevice, inst.TUNGateway())
	}
	if rep := s.restoreBackup(ctx); rep != nil {
		res.Network = rep
	}
	return res, nil
}

// StatusResult is status's reply.
type StatusResult struct {
	Version          string     `json:"version"`
	Sessions         []*session `json:"sessions"`
	BackupPresent    bool       `json:"backup_present"`
	DefaultInterface string     `json:"default_interface"`
	Events           []Event    `json:"events"`
}

func (s *Service) status(ctx context.Context, _ Peer, _ json.RawMessage) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	res := StatusResult{Version: s.Version, Sessions: []*session{}, Events: slices.Clone(s.events)}
	for _, name := range s.sessionNames() {
		res.Sessions = append(res.Sessions, s.sessions[name])
	}
	_, err := os.Stat(s.backupPath())
	res.BackupPresent = err == nil
	_, res.DefaultInterface = netstate.DefaultRoute(ctx, s.Runner)
	return res, nil
}

// endSession tears one session down. When it was the last one, the network
// backup is restored. The caller holds s.mu.
func (s *Service) endSession(ctx context.Context, name, reason string) Event {
	sess := s.sessions[name]
	delete(s.sessions, name)
	delete(s.missing, name)
	msg := fmt.Sprintf("%s session ended: %s", sess.Kind, reason)
	if sess.Kind == KindTUN {
		stopProcess(sess)
		os.Remove(filepath.Join(sess.dir, "core.pid"))
		if n := s.removeLeftoverRoutes(ctx, sess.Device, sess.Gateway); n > 0 {
			msg += fmt.Sprintf("; removed %d leftover routes via %s", n, sess.Gateway)
		}
	}
	rep := s.finishIfIdle(ctx)
	if sess.Kind == KindTUN {
		if left, err := netstate.RoutesVia(ctx, s.Runner, sess.Device, sess.Gateway); err == nil && len(left) > 0 {
			if rep == nil {
				rep = &netstate.Report{}
			}
			for _, r := range left {
				rep.Remaining = append(rep.Remaining, fmt.Sprintf("route %s via %s on %s could not be removed", r.Dest, r.Gateway, r.Netif))
			}
		}
	}
	if rep != nil {
		if rep.OK() {
			msg += "; network settings restored and verified"
		} else {
			msg += "; network NOT fully restored: " + strings.Join(rep.Remaining, "; ")
		}
	}
	return s.event(name, msg, rep)
}

func stopProcess(sess *session) {
	if sess.cmd == nil {
		return
	}
	select {
	case <-sess.exited:
		return
	default:
	}
	sess.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-sess.exited:
	case <-time.After(5 * time.Second):
		sess.cmd.Process.Kill()
		<-sess.exited
	}
}

func (s *Service) sessionNames() []string {
	names := make([]string, 0, len(s.sessions))
	for n := range s.sessions {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

func (s *Service) backupPath() string { return filepath.Join(s.Root, "backup.json") }

// ensureBackup snapshots the network unless a backup already exists. An
// existing backup predates every current change, so it is the one to keep.
func (s *Service) ensureBackup(ctx context.Context) error {
	if _, err := os.Stat(s.backupPath()); err == nil {
		return nil
	}
	snap, err := netstate.Take(ctx, s.Runner)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return err
	}
	tmp := s.backupPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.backupPath())
}

func (s *Service) finishIfIdle(ctx context.Context) *netstate.Report {
	if len(s.sessions) > 0 {
		return nil
	}
	return s.restoreBackup(ctx)
}

// restoreBackup restores and verifies the saved network state, deleting
// the backup only once the network matches it.
func (s *Service) restoreBackup(ctx context.Context) *netstate.Report {
	data, err := os.ReadFile(s.backupPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return &netstate.Report{Remaining: []string{err.Error()}}
	}
	var snap netstate.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return &netstate.Report{Remaining: []string{"corrupt backup: " + err.Error()}}
	}
	rep, err := netstate.Restore(ctx, s.Runner, snap)
	if err != nil {
		rep.Remaining = append(rep.Remaining, err.Error())
	}
	if rep.OK() {
		os.Remove(s.backupPath())
	}
	return &rep
}

func (s *Service) removeLeftoverRoutes(ctx context.Context, device, gateway string) int {
	routes, err := netstate.RoutesVia(ctx, s.Runner, device, gateway)
	if err != nil || len(routes) == 0 {
		return 0
	}
	for _, e := range netstate.RemoveRoutes(ctx, s.Runner, routes) {
		s.Log.Printf("remove route: %v", e)
	}
	return len(routes)
}

func (s *Service) killLeftoverCores() {
	pidfiles, _ := filepath.Glob(filepath.Join(s.Root, "run", "*", "core.pid"))
	for _, pf := range pidfiles {
		data, err := os.ReadFile(pf)
		if err != nil {
			continue
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		if pid > 0 && s.Alive(pid) && s.IsCore(pid) {
			syscall.Kill(pid, syscall.SIGTERM)
			for i := 0; i < 50 && s.Alive(pid); i++ {
				time.Sleep(100 * time.Millisecond)
			}
			if s.Alive(pid) {
				syscall.Kill(pid, syscall.SIGKILL)
			}
			s.event(filepath.Base(filepath.Dir(pf)), fmt.Sprintf("stopped leftover mihomo (pid %d)", pid), nil)
		}
		os.Remove(pf)
	}
}

// Recover is the startup self-check: it stops cores left by a previous
// helper, removes routes left on Clash Mihomac's TUN devices, and restores
// any network backup that was never restored.
func (s *Service) Recover(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	s.killLeftoverCores()
	for _, name := range instance.Slots() {
		inst, _ := instance.Get("", name)
		if n := s.removeLeftoverRoutes(ctx, inst.TUNDevice, inst.TUNGateway()); n > 0 {
			s.event(name, fmt.Sprintf("startup: removed %d leftover routes via %s", n, inst.TUNGateway()), nil)
		}
	}
	if rep := s.restoreBackup(ctx); rep != nil {
		msg := "startup: restored network settings left by a previous session"
		if !rep.OK() {
			msg = "startup: could not fully restore network settings: " + strings.Join(rep.Remaining, "; ")
		}
		s.event("", msg, rep)
	}
}

// Watch runs the watchdog until ctx is cancelled.
func (s *Service) Watch(ctx context.Context) {
	t := time.NewTicker(s.Poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}

// Tick runs one watchdog pass:
//   - a session whose client process has exited is ended
//   - a TUN session whose core has exited is ended
//   - every few passes, and right after a wake from sleep, TUN routes are
//     checked; if they are missing twice in a row the core is restarted
func (s *Service) Tick(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()

	now := time.Now()
	woke := !s.lastTick.IsZero() && s.Poll >= time.Second && now.Sub(s.lastTick) > 5*s.Poll
	s.lastTick = now
	s.ticks++

	for _, name := range s.sessionNames() {
		sess := s.sessions[name]
		if !s.Alive(sess.ClientPID) {
			s.endSession(ctx, name, fmt.Sprintf("client pid %d exited", sess.ClientPID))
			continue
		}
		if sess.Kind == KindTUN {
			select {
			case <-sess.exited:
				s.endSession(ctx, name, "mihomo exited unexpectedly (see "+filepath.Join(sess.dir, "mihomo.log")+")")
			default:
			}
		}
	}

	if !woke && s.ticks%3 != 0 {
		return
	}
	if woke {
		s.event("", "wake from sleep detected; checking routes", nil)
	}
	if _, iface := netstate.DefaultRoute(ctx, s.Runner); iface != s.lastIface {
		if s.lastIface != "" {
			s.event("", fmt.Sprintf("default interface changed from %s to %q", s.lastIface, iface), nil)
		}
		s.lastIface = iface
	}
	for _, name := range s.sessionNames() {
		sess := s.sessions[name]
		if sess.Kind != KindTUN {
			continue
		}
		routes, err := netstate.RoutesVia(ctx, s.Runner, sess.Device, "")
		if err != nil || len(routes) > 0 {
			s.missing[name] = 0
			continue
		}
		s.missing[name]++
		if s.missing[name] < 2 {
			continue
		}
		s.missing[name] = 0
		// Restart at most maxRestarts times per restartWindow; a core whose
		// routes keep vanishing has a real problem, and restarting it in a
		// loop would only churn the network.
		sess.restarts = slices.DeleteFunc(sess.restarts, func(t time.Time) bool { return now.Sub(t) > restartWindow })
		if len(sess.restarts) >= maxRestarts {
			s.endSession(ctx, name, fmt.Sprintf("TUN routes kept disappearing (%d restarts in %s); stopped to avoid a restart loop", maxRestarts, restartWindow))
			continue
		}
		sess.restarts = append(sess.restarts, now)
		stopProcess(sess)
		s.removeLeftoverRoutes(ctx, sess.Device, sess.Gateway)
		if err := s.startCore(sess, filepath.Join(sess.dir, "mihomo"), filepath.Join(sess.dir, "runtime.yaml")); err != nil {
			s.endSession(ctx, name, "could not restart core after its routes disappeared: "+err.Error())
			continue
		}
		s.event(name, fmt.Sprintf("TUN routes on %s disappeared; restarted core (pid %d)", sess.Device, sess.CorePID), nil)
	}
}

// Shutdown ends every session, restoring the network.
func (s *Service) Shutdown(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	for _, name := range s.sessionNames() {
		s.endSession(ctx, name, "helper shutting down")
	}
}

func (s *Service) event(inst, msg string, rep *netstate.Report) Event {
	ev := Event{Time: time.Now(), Instance: inst, Message: msg, Network: rep}
	s.events = append(s.events, ev)
	if len(s.events) > 50 {
		s.events = s.events[len(s.events)-50:]
	}
	if inst != "" {
		s.Log.Printf("[%s] %s", inst, msg)
	} else {
		s.Log.Print(msg)
	}
	return ev
}

// handOver lets the allowed user read a file the helper created.
func (s *Service) handOver(path string) {
	if s.UID >= 0 && os.Geteuid() == 0 {
		os.Chown(path, s.UID, -1)
	}
}

func execCore(bin string, args []string, logf *os.File) (*exec.Cmd, error) {
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd, cmd.Start()
}

func copyFile(in *os.File, dst string, mode os.FileMode) error {
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return err
	}
	os.Remove(dst)
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func procName(pid int) string {
	out, err := exec.Command("/bin/ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return ""
	}
	return filepath.Base(strings.TrimSpace(string(out)))
}
