package core

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeRelease(t *testing.T, payload []byte) (*httptest.Server, string) {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(payload)
	zw.Close()
	gz := buf.Bytes()
	sum := sha256.Sum256(gz)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v9.9.9/"+AssetName("v9.9.9", "arm64") {
			http.NotFound(w, r)
			return
		}
		w.Write(gz)
	}))
	t.Cleanup(srv.Close)
	return srv, hex.EncodeToString(sum[:])
}

func TestInstallVerifiesAndExtracts(t *testing.T) {
	srv, sum := fakeRelease(t, []byte("#!/bin/sh\necho mihomo\n"))
	m := &Manager{Dir: t.TempDir(), BaseURL: srv.URL, Client: srv.Client()}

	path, err := m.Install(context.Background(), "v9.9.9", "arm64", sum)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "#!/bin/sh\necho mihomo\n" {
		t.Fatalf("binary = %q, %v", got, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("binary is not executable: %v", info.Mode())
	}
	versions, err := m.Installed()
	if err != nil || len(versions) != 1 || versions[0] != "v9.9.9" {
		t.Errorf("Installed() = %v, %v", versions, err)
	}
}

func TestInstallRejectsChecksumMismatch(t *testing.T) {
	srv, _ := fakeRelease(t, []byte("tampered"))
	m := &Manager{Dir: t.TempDir(), BaseURL: srv.URL, Client: srv.Client()}

	wrong := strings.Repeat("0", 64)
	if _, err := m.Install(context.Background(), "v9.9.9", "arm64", wrong); err == nil {
		t.Fatal("expected checksum mismatch")
	}
	if m.IsInstalled("v9.9.9") {
		t.Error("binary installed despite checksum mismatch")
	}
}

func TestInstallRequiresChecksumForUnpinnedVersion(t *testing.T) {
	m := &Manager{Dir: t.TempDir(), BaseURL: "http://unused.invalid", Client: http.DefaultClient}
	if _, err := m.Install(context.Background(), "v9.9.9", "arm64", ""); err == nil {
		t.Fatal("expected error for unpinned version without checksum")
	}
}

func TestInstallRejectsBadVersion(t *testing.T) {
	m := &Manager{Dir: t.TempDir(), BaseURL: "http://unused.invalid", Client: http.DefaultClient}
	for _, v := range []string{"../../etc", "latest", "1.19.31", "v1.19"} {
		if _, err := m.Install(context.Background(), v, "arm64", "ab"); err == nil {
			t.Errorf("version %q accepted", v)
		}
	}
}

func TestDefaultVersionIsPinnedForBothArches(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		if _, ok := PinnedSHA256(DefaultVersion, arch); !ok {
			t.Errorf("DefaultVersion %s has no pinned checksum for %s", DefaultVersion, arch)
		}
		if _, ok := pinnedBinary[DefaultVersion][arch]; !ok {
			t.Errorf("DefaultVersion %s has no pinned binary checksum for %s", DefaultVersion, arch)
		}
	}
}

func TestVerifyBinaryRejectsUnpinned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mihomo")
	os.WriteFile(path, []byte("#!/bin/sh\nid\n"), 0o755)
	if _, err := VerifyBinary(path); err == nil {
		t.Error("unpinned binary accepted")
	}
}
