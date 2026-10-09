package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Each instance records which mihomo version it runs in <dir>/core-version
// and the versions it ran before in <dir>/core-history (newest last), so a
// bad upgrade can be rolled back with one command.

const (
	selectedFile = "core-version"
	historyFile  = "core-history"
	maxHistory   = 20
)

// Selected returns the version an instance is set to run, or def if none
// has been chosen.
func Selected(instDir, def string) string {
	data, err := os.ReadFile(filepath.Join(instDir, selectedFile))
	if err != nil {
		return def
	}
	if v := strings.TrimSpace(string(data)); versionRE.MatchString(v) {
		return v
	}
	return def
}

// History lists the versions an instance ran before its current one,
// oldest first.
func History(instDir string) []string {
	data, err := os.ReadFile(filepath.Join(instDir, historyFile))
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Fields(string(data)) {
		if versionRE.MatchString(l) {
			out = append(out, l)
		}
	}
	return out
}

// Select makes version the one an instance runs, remembering the previous
// one for Rollback. current is what the instance is running now (the
// stored choice, or the default).
func (m *Manager) Select(instDir, current, version string) error {
	if !versionRE.MatchString(version) {
		return fmt.Errorf("invalid version %q: want vX.Y.Z", version)
	}
	if !m.IsInstalled(version) {
		return fmt.Errorf("mihomo %s is not installed; run `mihomac core install --version %s` first", version, version)
	}
	if err := os.MkdirAll(instDir, 0o700); err != nil {
		return err
	}
	if version != current {
		hist := append(History(instDir), current)
		if len(hist) > maxHistory {
			hist = hist[len(hist)-maxHistory:]
		}
		if err := writeAtomic(filepath.Join(instDir, historyFile), strings.Join(hist, "\n")+"\n"); err != nil {
			return err
		}
	}
	return writeAtomic(filepath.Join(instDir, selectedFile), version+"\n")
}

// Rollback switches an instance back to the most recent earlier version
// that is still installed, and returns it. The version rolled back from is
// not kept in the history, so repeated rollbacks keep walking backwards.
func (m *Manager) Rollback(instDir, current string) (string, error) {
	hist := History(instDir)
	for i := len(hist) - 1; i >= 0; i-- {
		v := hist[i]
		if v == current || !m.IsInstalled(v) {
			continue
		}
		rest := strings.Join(hist[:i], "\n")
		if rest != "" {
			rest += "\n"
		}
		if err := writeAtomic(filepath.Join(instDir, historyFile), rest); err != nil {
			return "", err
		}
		if err := writeAtomic(filepath.Join(instDir, selectedFile), v+"\n"); err != nil {
			return "", err
		}
		return v, nil
	}
	return "", errors.New("no earlier installed mihomo version to roll back to")
}

// Remove deletes an installed version. The caller must make sure no
// instance is running it.
func (m *Manager) Remove(version string) error {
	if !versionRE.MatchString(version) {
		return fmt.Errorf("invalid version %q: want vX.Y.Z", version)
	}
	if !m.IsInstalled(version) {
		return fmt.Errorf("mihomo %s is not installed", version)
	}
	return os.RemoveAll(filepath.Join(m.Dir, version))
}

func writeAtomic(path, content string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
