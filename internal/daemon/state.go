package daemon

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/instance"
)

// State describes a running instance. The daemon writes it once mihomo is
// ready and removes it on exit.
type State struct {
	Instance       string    `json:"instance"`
	PID            int       `json:"pid"`
	CorePID        int       `json:"core_pid"`
	Mode           string    `json:"mode"`
	CoreVersion    string    `json:"core_version"`
	ConfigPath     string    `json:"config_path"`
	MixedPort      int       `json:"mixed_port"`
	ControllerPort int       `json:"controller_port"`
	GUIURL         string    `json:"gui_url"`
	StartedAt      time.Time `json:"started_at"`
}

func statePath(inst instance.Instance) string { return inst.Path("state.json") }

// ReadState returns the saved state, or ok=false if none exists.
func ReadState(inst instance.Instance) (st State, ok bool, err error) {
	data, err := os.ReadFile(statePath(inst))
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, false, err
	}
	return st, true, nil
}

func writeState(inst instance.Instance, st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(inst) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath(inst))
}

func removeState(inst instance.Instance) error {
	err := os.Remove(statePath(inst))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// IsRunning reports whether st's daemon process is alive. The process name
// is checked too, so a PID reused by an unrelated program doesn't count.
func IsRunning(st State) bool {
	return processIs(st.PID, "mihomac")
}

// Stop terminates the instance's daemon, which stops its core and restores
// the network. If the daemon died without cleaning up, a user-mode core
// wrapper still running is stopped too; a TUN core belongs to the helper,
// whose watchdog has already ended that session. It reports whether
// anything was stopped.
func Stop(inst instance.Instance, timeout time.Duration) (bool, error) {
	st, ok, err := ReadState(inst)
	if err != nil || !ok {
		return false, err
	}
	stopped := false
	procs := []struct {
		pid  int
		name string
	}{{st.PID, "mihomac"}}
	if st.Mode != "tun" {
		procs = append(procs, struct {
			pid  int
			name string
		}{st.CorePID, "mihomac"})
	}
	for _, p := range procs {
		if !processIs(p.pid, p.name) {
			continue
		}
		if err := terminate(p.pid, timeout); err != nil {
			return stopped, err
		}
		stopped = true
	}
	return stopped, removeState(inst)
}

// terminate sends SIGTERM, then SIGKILL if pid is still alive after timeout.
func terminate(pid int, timeout time.Duration) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	if waitGone(pid, timeout) {
		return nil
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	waitGone(pid, 2*time.Second)
	return nil
}

func waitGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !alive(pid) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !alive(pid)
}

func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func processIs(pid int, name string) bool {
	if !alive(pid) {
		return false
	}
	out, err := exec.Command("/bin/ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	return err == nil && filepath.Base(strings.TrimSpace(string(out))) == name
}
