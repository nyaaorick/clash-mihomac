// Package core downloads, verifies, and stores mihomo binaries.
//
// Each version lives in its own directory so older versions stay available
// for rollback. Downloads are verified against SHA-256 checksums pinned in
// this file; an unpinned version needs an explicit checksum from the caller.
package core

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// DefaultVersion is the mihomo version Clash Mihomac is tested against.
const DefaultVersion = "v1.19.31"

// DefaultBaseURL is where mihomo release assets are downloaded from.
const DefaultBaseURL = "https://github.com/MetaCubeX/mihomo/releases/download"

// pinned maps version -> GOARCH -> SHA-256 of the release's .gz asset,
// taken from the digests GitHub publishes for each release asset.
var pinned = map[string]map[string]string{
	"v1.19.31": {
		"arm64": "d131f44b3deb2a8356f7ac75048ad67a10d53243323951c4f3cda7b672922963",
		"amd64": "3546681ebef3415e5dcbe7210a61aa80748136e95e6552768fd883df345508ed",
	},
}

// pinnedBinary maps version -> GOARCH -> SHA-256 of the decompressed
// binary. The privileged helper only runs binaries listed here as root.
var pinnedBinary = map[string]map[string]string{
	"v1.19.31": {
		"arm64": "fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090",
		"amd64": "1f5cd540bf6de98eb42138359490edfa163ae69c9427330acf7a09b734dadde4",
	},
}

// VerifyBinary checks that the file at path is a pinned mihomo binary and
// returns its version.
func VerifyBinary(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	for version, arches := range pinnedBinary {
		for _, want := range arches {
			if sum == want {
				return version, nil
			}
		}
	}
	return "", fmt.Errorf("%s is not a pinned mihomo binary (sha256 %s)", path, sum)
}

var versionRE = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// Manager stores mihomo binaries under Dir.
type Manager struct {
	Dir     string
	BaseURL string
	Client  *http.Client
}

// NewManager returns a Manager that stores cores under home/cores.
func NewManager(home string) *Manager {
	return &Manager{Dir: filepath.Join(home, "cores"), BaseURL: DefaultBaseURL, Client: http.DefaultClient}
}

// AssetName is the release asset name for a version and GOARCH.
func AssetName(version, arch string) string {
	return fmt.Sprintf("mihomo-darwin-%s-%s.gz", arch, version)
}

// PinnedSHA256 returns the pinned checksum for a version and GOARCH.
func PinnedSHA256(version, arch string) (string, bool) {
	sum, ok := pinned[version][arch]
	return sum, ok
}

// BinaryPath is where the binary for version is (or would be) stored.
func (m *Manager) BinaryPath(version string) string {
	return filepath.Join(m.Dir, version, "mihomo")
}

// IsInstalled reports whether version has been installed.
func (m *Manager) IsInstalled(version string) bool {
	info, err := os.Stat(m.BinaryPath(version))
	return err == nil && info.Mode().IsRegular()
}

// Installed lists installed versions in sorted order.
func (m *Manager) Installed() ([]string, error) {
	entries, err := os.ReadDir(m.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var versions []string
	for _, e := range entries {
		if e.IsDir() && versionRE.MatchString(e.Name()) && m.IsInstalled(e.Name()) {
			versions = append(versions, e.Name())
		}
	}
	sort.Strings(versions)
	return versions, nil
}

// Install downloads version for arch, verifies it, and stores it.
// If sha256hex is empty the pinned checksum is used; installing a version
// with no pinned checksum and no explicit one is refused.
func (m *Manager) Install(ctx context.Context, version, arch, sha256hex string) (string, error) {
	if !versionRE.MatchString(version) {
		return "", fmt.Errorf("invalid version %q: want vX.Y.Z", version)
	}
	want := strings.ToLower(sha256hex)
	if want == "" {
		sum, ok := PinnedSHA256(version, arch)
		if !ok {
			return "", fmt.Errorf("no pinned checksum for mihomo %s (%s); pass the SHA-256 of %s explicitly", version, arch, AssetName(version, arch))
		}
		want = sum
	}

	dir := filepath.Join(m.Dir, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/%s/%s", strings.TrimRight(m.BaseURL, "/"), version, AssetName(version, arch))
	gz, err := m.download(ctx, url, dir, want)
	if err != nil {
		return "", err
	}
	defer os.Remove(gz)

	dst := m.BinaryPath(version)
	if err := gunzip(gz, dst+".tmp"); err != nil {
		os.Remove(dst + ".tmp")
		return "", err
	}
	if err := os.Rename(dst+".tmp", dst); err != nil {
		return "", err
	}
	return dst, nil
}

// download fetches url into a temp file in dir and checks its SHA-256.
func (m *Manager) download(ctx context.Context, url, dir, want string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: %s", url, resp.Status)
	}

	f, err := os.CreateTemp(dir, "download-*.gz")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(f.Name())
		return "", fmt.Errorf("checksum mismatch for %s: got %s, want %s", url, got, want)
	}
	return f.Name(), nil
}

func gunzip(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		return fmt.Errorf("decompress %s: %w", src, err)
	}
	defer zr.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, zr); err != nil {
		out.Close()
		return fmt.Errorf("decompress %s: %w", src, err)
	}
	return out.Close()
}
