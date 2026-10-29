package daemon

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/nyaaorick/clash-mihomac/internal/gui"
)

// DaemonLog is the daemon's own log file under the data directory.
const DaemonLog = "daemon.log"

// maxLogBytes caps how much of a log is read, from the end.
const maxLogBytes = 256 << 10

// LogSources are the logs the GUI and CLI can show.
var LogSources = []string{"daemon", "verge"}

// logPath resolves a log source to a file.
func (d *Daemon) logPath(source string) (string, error) {
	switch source {
	case "daemon":
		return filepath.Join(d.home, DaemonLog), nil
	case "verge":
		return d.o.Verge.LogFile(), nil
	}
	return "", fmt.Errorf("unknown log %q (want daemon or verge)", source)
}

// ReadLog returns the last n lines of the file at path.
func ReadLog(path string, n int) ([]string, error) {
	if n <= 0 || n > 2000 {
		n = 200
	}
	f, err := os.Open(path)
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

// handleLogs serves GET /api/logs?source=&lines=. Logs can mention
// destinations and paths, so agents don't get them.
func (d *Daemon) handleLogs(w http.ResponseWriter, r *http.Request) {
	if gui.ScopeFrom(r.Context()) != gui.ScopeFull {
		httpError(w, http.StatusForbidden, "logs are only available to the person using the GUI or CLI")
		return
	}
	source := firstNonEmpty(r.URL.Query().Get("source"), "daemon")
	path, err := d.logPath(source)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	lines, err := ReadLog(path, n)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]any{"source": source, "path": path, "lines": lines})
}
