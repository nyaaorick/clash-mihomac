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
)

// State describes the running daemon. It is written once the API is up
// and removed on exit, so the CLI knows where to find the daemon.
type State struct {
	PID       int       `json:"pid"`
	GUIURL    string    `json:"gui_url"`
	VergeDir  string    `json:"verge_dir"`
	StartedAt time.Time `json:"started_at"`
}

// StateFile is the state file's name under the data directory.
const StateFile = "state.json"

func statePath(home string) string { return filepath.Join(home, StateFile) }

// ReadState returns the saved state, or ok=false if none exists.
func ReadState(home string) (st State, ok bool, err error) {
	data, err := os.ReadFile(statePath(home))
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

func writeState(home string, st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(home) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath(home))
}

func removeState(home string) error {
	err := os.Remove(statePath(home))
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

// Stop terminates the daemon. Nothing else needs cleaning up: mihomo,
// TUN, and the system proxy belong to Clash Verge and keep running. It
// reports whether anything was stopped.
func Stop(home string, timeout time.Duration) (bool, error) {
	st, ok, err := ReadState(home)
	if err != nil || !ok {
		return false, err
	}
	stopped := false
	if processIs(st.PID, "mihomac") {
		if err := terminate(st.PID, timeout); err != nil {
			return false, err
		}
		stopped = true
	}
	return stopped, removeState(home)
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
