package daemon

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/core"
	"github.com/nyaaorick/clash-mihomac/internal/gui"
	"github.com/nyaaorick/clash-mihomac/internal/instance"
)

// InstanceInfo is one instance as listed by GET /api/instances: built-in
// instances and user profiles, running or not.
type InstanceInfo struct {
	Name        string    `json:"name"`
	Label       string    `json:"label"`
	Profile     bool      `json:"profile"`
	Running     bool      `json:"running"`
	Mode        string    `json:"mode,omitempty"`
	PID         int       `json:"pid,omitempty"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	CoreVersion string    `json:"core_version"` // running version, else the selected one
	MixedPort   int       `json:"mixed_port"`
	TUNDevice   string    `json:"tun_device"`
	GUIPort     int       `json:"gui_port"`
	Current     bool      `json:"current,omitempty"` // the instance serving this request
}

// ListInstances reports every instance under home. self marks the one
// that is asking.
func ListInstances(home, self string) ([]InstanceInfo, error) {
	all, err := instance.List(home)
	if err != nil {
		return nil, err
	}
	out := make([]InstanceInfo, 0, len(all))
	for _, inst := range all {
		info := InstanceInfo{
			Name: inst.Name, Label: inst.Label(), Profile: instance.IsProfile(inst.Name),
			CoreVersion: core.Selected(inst.Dir, core.DefaultVersion),
			MixedPort:   inst.MixedPort, TUNDevice: inst.TUNDevice, GUIPort: inst.GUIPort,
			Current: inst.Name == self,
		}
		if st, ok, _ := ReadState(inst); ok && IsRunning(st) {
			info.Running, info.Mode, info.PID, info.StartedAt, info.CoreVersion = true, st.Mode, st.PID, st.StartedAt, st.CoreVersion
		}
		out = append(out, info)
	}
	return out, nil
}

// Log sources an instance keeps.
var logFiles = map[string]string{"daemon": "daemon.log", "core": "mihomo.log"}

// maxLogBytes caps how much of a log is read, from the end.
const maxLogBytes = 256 << 10

// ReadLog returns the last n lines of one of an instance's logs.
func ReadLog(inst instance.Instance, source string, n int) ([]string, error) {
	name, ok := logFiles[source]
	if !ok {
		return nil, fmt.Errorf("unknown log %q (want daemon or core)", source)
	}
	if n <= 0 || n > 2000 {
		n = 200
	}
	f, err := os.Open(inst.Path(name))
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := int64(0)
	if info.Size() > maxLogBytes {
		start = info.Size() - maxLogBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	lines := splitLines(string(data))
	if start > 0 && len(lines) > 0 {
		lines = lines[1:] // the first line was cut in half
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

func splitLines(s string) []string {
	lines := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func (d *Daemon) handleInstances(w http.ResponseWriter, r *http.Request) {
	home, err := instance.Home()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	list, err := ListInstances(home, d.inst.Name)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, list)
}

// handleLogs serves GET /api/logs?instance=&source=&lines=. Logs can
// mention destinations and paths, so agents don't get them.
func (d *Daemon) handleLogs(w http.ResponseWriter, r *http.Request) {
	if gui.ScopeFrom(r.Context()) != gui.ScopeFull {
		httpError(w, http.StatusForbidden, "logs are only available to the person using the GUI or CLI")
		return
	}
	home, err := instance.Home()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	name := r.URL.Query().Get("instance")
	if name == "" {
		name = d.inst.Name
	}
	inst, err := instance.Get(home, name)
	if err != nil {
		httpError(w, http.StatusNotFound, err.Error())
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	lines, err := ReadLog(inst, firstNonEmpty(r.URL.Query().Get("source"), "daemon"), n)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]any{"instance": inst.Name, "lines": lines})
}
