package core

import (
	"os"
	"path/filepath"
	"testing"
)

func fakeInstall(t *testing.T, m *Manager, versions ...string) {
	t.Helper()
	for _, v := range versions {
		if err := os.MkdirAll(filepath.Dir(m.BinaryPath(v)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(m.BinaryPath(v), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSelectAndRollback(t *testing.T) {
	m := NewManager(t.TempDir())
	fakeInstall(t, m, "v1.0.0", "v1.1.0", "v1.2.0")
	dir := filepath.Join(t.TempDir(), "inst")

	if got := Selected(dir, "v1.0.0"); got != "v1.0.0" {
		t.Errorf("default = %s", got)
	}
	if err := m.Select(dir, "v1.0.0", "v1.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := m.Select(dir, "v1.1.0", "v1.2.0"); err != nil {
		t.Fatal(err)
	}
	if got := Selected(dir, "v1.0.0"); got != "v1.2.0" {
		t.Errorf("selected = %s", got)
	}
	v, err := m.Rollback(dir, "v1.2.0")
	if err != nil || v != "v1.1.0" {
		t.Fatalf("Rollback = %s, %v", v, err)
	}
	v, err = m.Rollback(dir, "v1.1.0")
	if err != nil || v != "v1.0.0" {
		t.Fatalf("second Rollback = %s, %v", v, err)
	}
	if _, err := m.Rollback(dir, "v1.0.0"); err == nil {
		t.Error("rollback with empty history should fail")
	}
}

func TestRollbackSkipsRemovedVersions(t *testing.T) {
	m := NewManager(t.TempDir())
	fakeInstall(t, m, "v1.0.0", "v1.1.0", "v1.2.0")
	dir := t.TempDir()
	m.Select(dir, "v1.0.0", "v1.1.0")
	m.Select(dir, "v1.1.0", "v1.2.0")
	if err := m.Remove("v1.1.0"); err != nil {
		t.Fatal(err)
	}
	v, err := m.Rollback(dir, "v1.2.0")
	if err != nil || v != "v1.0.0" {
		t.Errorf("Rollback = %s, %v; want v1.0.0", v, err)
	}
}

func TestSelectRejectsBadInput(t *testing.T) {
	m := NewManager(t.TempDir())
	dir := t.TempDir()
	if err := m.Select(dir, "v1.0.0", "v9.9.9"); err == nil {
		t.Error("selecting an uninstalled version should fail")
	}
	for _, bad := range []string{"../x", "1.0.0", "v1.0", ""} {
		if err := m.Select(dir, "v1.0.0", bad); err == nil {
			t.Errorf("Select(%q) accepted", bad)
		}
		if err := m.Remove(bad); err == nil {
			t.Errorf("Remove(%q) accepted", bad)
		}
	}
}

func TestSelectedIgnoresGarbage(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "core-version"), []byte("../../etc/passwd\n"), 0o600)
	if got := Selected(dir, "v1.0.0"); got != "v1.0.0" {
		t.Errorf("Selected = %q", got)
	}
}
