package verge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ReleasesAPI is where the latest Clash Verge Rev release is described.
const ReleasesAPI = "https://api.github.com/repos/clash-verge-rev/clash-verge-rev/releases/latest"

// MaxDownload bounds the installer download.
const MaxDownload = 512 << 20

// TeamID is the Apple Developer Team that signs Clash Verge Rev releases.
// The installer only accepts an app signed by it; a valid signature and
// notarization from anyone else is not enough.
const TeamID = "JPH3Z7PPBB"

// signingRequirement is the codesign requirement for TeamID.
var signingRequirement = fmt.Sprintf(`anchor apple generic and certificate leaf[subject.OU] = %q`, TeamID)

// Release is one downloadable build of Clash Verge Rev.
type Release struct {
	Tag   string `json:"tag"`
	Asset string `json:"asset"`
	URL   string `json:"url"`
	Size  int64  `json:"size"`
}

// AssetSuffix is the dmg name ending for a Go architecture.
func AssetSuffix(arch string) (string, error) {
	switch arch {
	case "arm64":
		return "_aarch64.dmg", nil
	case "amd64":
		return "_x64.dmg", nil
	}
	return "", fmt.Errorf("no Clash Verge build for %s", arch)
}

// LatestRelease asks GitHub for the newest release and picks the macOS
// disk image for arch.
func LatestRelease(ctx context.Context, client *http.Client, api, arch string) (Release, error) {
	suffix, err := AssetSuffix(arch)
	if err != nil {
		return Release{}, err
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if api == "" {
		api = ReleasesAPI
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "clash-mihomac")
	resp, err := client.Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("fetch release list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("fetch release list: %s", resp.Status)
	}
	var body struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return Release{}, fmt.Errorf("parse release list: %w", err)
	}
	for _, a := range body.Assets {
		if strings.HasSuffix(a.Name, suffix) && !strings.Contains(a.Name, "fixed_webview") {
			if !strings.HasPrefix(a.URL, "https://") {
				return Release{}, fmt.Errorf("release asset %s has a non-https URL", a.Name)
			}
			if strings.ContainsAny(a.Name, `/\`) || a.Name != filepath.Base(a.Name) {
				return Release{}, fmt.Errorf("release asset name %q is not a plain file name", a.Name)
			}
			return Release{Tag: body.Tag, Asset: a.Name, URL: a.URL, Size: a.Size}, nil
		}
	}
	return Release{}, fmt.Errorf("release %s has no macOS %s disk image", body.Tag, arch)
}

// InstallOptions configure Install.
type InstallOptions struct {
	Dest     string // directory to install into; default /Applications
	Arch     string // default runtime.GOARCH
	API      string // default ReleasesAPI
	HTTP     *http.Client
	Run      Runner
	Work     string // scratch directory; default a fresh temp dir
	Replace  bool   // replace an installed copy (Verge must be closed)
	Progress func(done, total int64)
}

// Install downloads the latest release, checks that the app inside the
// disk image carries Apple's signature and passes Gatekeeper, and copies
// it into Dest. Nothing is copied before the checks pass, and the image
// is only mounted read-only. It returns the installed app.
func Install(ctx context.Context, o InstallOptions) (App, error) {
	if o.Dest == "" {
		o.Dest = "/Applications"
	}
	if o.Arch == "" {
		o.Arch = runtime.GOARCH
	}
	if o.Run == nil {
		return App{}, errors.New("install needs a command runner")
	}
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 15 * time.Minute}
	}
	if o.HTTP.CheckRedirect == nil {
		o.HTTP.CheckRedirect = httpsOnlyRedirect
	}
	rel, err := LatestRelease(ctx, o.HTTP, o.API, o.Arch)
	if err != nil {
		return App{}, err
	}
	if rel.Size > MaxDownload {
		return App{}, fmt.Errorf("%s is %d bytes, larger than the %d byte limit", rel.Asset, rel.Size, MaxDownload)
	}

	work := o.Work
	if work == "" {
		if work, err = os.MkdirTemp("", "mihomac-verge-"); err != nil {
			return App{}, err
		}
		defer os.RemoveAll(work)
	}
	dmg := filepath.Join(work, rel.Asset)
	if err := download(ctx, o.HTTP, rel, dmg, o.Progress); err != nil {
		return App{}, err
	}

	mnt := filepath.Join(work, "mnt")
	if err := os.MkdirAll(mnt, 0o700); err != nil {
		return App{}, err
	}
	if _, err := o.Run.Run(ctx, "/usr/bin/hdiutil", "attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", mnt, dmg); err != nil {
		return App{}, fmt.Errorf("mount %s: %w", rel.Asset, err)
	}
	defer func() {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		o.Run.Run(dctx, "/usr/bin/hdiutil", "detach", "-force", mnt)
	}()

	src, err := appInImage(mnt)
	if err != nil {
		return App{}, err
	}
	if _, err := o.Run.Run(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", "-R="+signingRequirement, src); err != nil {
		return App{}, fmt.Errorf("%s is not signed by Clash Verge Rev's developer (team %s): %w", rel.Asset, TeamID, err)
	}
	if _, err := o.Run.Run(ctx, "/usr/sbin/spctl", "--assess", "--type", "execute", src); err != nil {
		return App{}, fmt.Errorf("%s is not accepted by Gatekeeper (not notarized?): %w", rel.Asset, err)
	}
	if _, err := InspectApp(ctx, o.Run, src); err != nil {
		return App{}, err
	}

	dst := filepath.Join(o.Dest, filepath.Base(src))
	_, statErr := os.Stat(dst)
	exists := statErr == nil
	if exists {
		if !o.Replace {
			return App{}, fmt.Errorf("%s already exists; pass --replace to install over it", dst)
		}
		if Running(ctx, o.Run) {
			return App{}, errors.New(AppName + " is running; quit it before replacing it")
		}
	}
	// Copy next to the destination first, then swap, so a failed copy
	// never leaves the user with half an app and no old one.
	fresh := dst + ".new"
	os.RemoveAll(fresh)
	if _, err := o.Run.Run(ctx, "/usr/bin/ditto", src, fresh); err != nil {
		os.RemoveAll(fresh)
		return App{}, fmt.Errorf("copy to %s: %w", o.Dest, err)
	}
	if _, err := InspectApp(ctx, o.Run, fresh); err != nil {
		os.RemoveAll(fresh)
		return App{}, err
	}
	old := dst + ".old"
	if exists {
		os.RemoveAll(old)
		if err := os.Rename(dst, old); err != nil {
			os.RemoveAll(fresh)
			return App{}, fmt.Errorf("move the old %s aside: %w", dst, err)
		}
	}
	if err := os.Rename(fresh, dst); err != nil {
		if exists {
			os.Rename(old, dst)
		}
		os.RemoveAll(fresh)
		return App{}, fmt.Errorf("put the new app in place: %w", err)
	}
	if exists {
		os.RemoveAll(old)
	}
	return InspectApp(ctx, o.Run, dst)
}

// httpsOnlyRedirect refuses a redirect that leaves https.
func httpsOnlyRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-https %s", req.URL)
	}
	return nil
}

// appInImage finds the single .app bundle at the top of a mounted image.
func appInImage(mnt string) (string, error) {
	entries, err := os.ReadDir(mnt)
	if err != nil {
		return "", err
	}
	var apps []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".app") {
			apps = append(apps, filepath.Join(mnt, e.Name()))
		}
	}
	if len(apps) != 1 {
		return "", fmt.Errorf("expected one app in the disk image, found %d", len(apps))
	}
	return apps[0], nil
}

func download(ctx context.Context, client *http.Client, rel Release, path string, progress func(done, total int64)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rel.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "clash-mihomac")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", rel.Asset, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", rel.Asset, resp.Status)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	var done int64
	buf := make([]byte, 256<<10)
	r := io.LimitReader(resp.Body, MaxDownload+1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			done += int64(n)
			if done > MaxDownload {
				return fmt.Errorf("%s exceeds the %d byte download limit", rel.Asset, MaxDownload)
			}
			if progress != nil {
				progress(done, rel.Size)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("download %s: %w", rel.Asset, err)
		}
	}
	if rel.Size > 0 && done != rel.Size {
		return fmt.Errorf("download %s: got %d bytes, release lists %d", rel.Asset, done, rel.Size)
	}
	return f.Close()
}
