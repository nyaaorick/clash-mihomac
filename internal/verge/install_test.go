package verge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installRunner fakes the macOS tools the installer drives. Mounting the
// image creates an app bundle under the mountpoint; ditto copies it.
type installRunner struct {
	calls    []string
	rejectBy string // "codesign" or "spctl" makes that check fail
	bundleID string
}

func (r *installRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, filepath.Base(name)+" "+strings.Join(args, " "))
	switch filepath.Base(name) {
	case "hdiutil":
		if args[0] == "attach" {
			mnt := args[len(args)-2]
			os.MkdirAll(filepath.Join(mnt, "Clash Verge.app", "Contents"), 0o700)
			os.WriteFile(filepath.Join(mnt, "Clash Verge.app", "Contents", "Info.plist"), []byte("plist"), 0o600)
		}
	case "codesign", "spctl":
		if r.rejectBy == filepath.Base(name) {
			return "rejected", context.DeadlineExceeded
		}
	case "plutil":
		id := r.bundleID
		if id == "" {
			id = BundleID
		}
		out, _ := json.Marshal(map[string]string{"CFBundleShortVersionString": "2.5.8", "CFBundleIdentifier": id})
		return string(out), nil
	case "ditto":
		os.MkdirAll(filepath.Join(args[1], "Contents"), 0o700)
	case "pgrep":
		return "", context.DeadlineExceeded
	}
	return "", nil
}

func releaseServer(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v2.5.8",
				"assets": []map[string]any{
					{"name": "Clash.Verge_2.5.8_x64.dmg", "browser_download_url": "https://example.invalid/x64", "size": 1},
					{"name": "Clash.Verge_2.5.8_aarch64_fixed_webview2-setup.exe", "browser_download_url": "https://example.invalid/w", "size": 1},
					{"name": "Clash.Verge_2.5.8_aarch64.dmg", "browser_download_url": strings.Replace(srv.URL, "http://", "https://", 1) + "/dmg", "size": len(payload)},
				},
			})
		case "/dmg":
			w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The release list demands https; the test server is http, so point the
// client's transport at it regardless of scheme.
func plainClient(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: &rewriteTransport{base: srv.URL}}
}

type rewriteTransport struct{ base string }

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	u.Scheme, u.Host = "http", strings.TrimPrefix(t.base, "http://")
	r2 := req.Clone(req.Context())
	r2.URL = &u
	return http.DefaultTransport.RoundTrip(r2)
}

func TestLatestReleasePicksArchDMG(t *testing.T) {
	srv := releaseServer(t, []byte("dmg"))
	rel, err := LatestRelease(context.Background(), plainClient(srv), srv.URL+"/latest", "arm64")
	if err != nil || rel.Asset != "Clash.Verge_2.5.8_aarch64.dmg" || rel.Tag != "v2.5.8" || rel.Size != 3 {
		t.Fatalf("release = %+v, %v", rel, err)
	}
	if _, err := LatestRelease(context.Background(), plainClient(srv), srv.URL+"/latest", "386"); err == nil {
		t.Error("unknown arch must fail")
	}
}

func TestInstallVerifiesBeforeCopying(t *testing.T) {
	payload := []byte("not really a dmg")
	srv := releaseServer(t, payload)
	dest := t.TempDir()
	r := &installRunner{}
	var last int64
	app, err := Install(context.Background(), InstallOptions{
		Dest: dest, Arch: "arm64", API: srv.URL + "/latest", HTTP: plainClient(srv), Run: r, Work: t.TempDir(),
		Progress: func(done, total int64) { last = done },
	})
	if err != nil {
		t.Fatal(err)
	}
	if app.Path != filepath.Join(dest, "Clash Verge.app") || app.Version != "2.5.8" {
		t.Errorf("app = %+v", app)
	}
	if last != int64(len(payload)) {
		t.Errorf("progress stopped at %d", last)
	}
	joined := strings.Join(r.calls, "\n")
	for _, want := range []string{"hdiutil attach -nobrowse -readonly", "codesign --verify --deep --strict -R=anchor apple generic and certificate leaf[subject.OU] = \"JPH3Z7PPBB\"", "spctl --assess --type execute", "ditto ", "hdiutil detach"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
	if strings.Index(joined, "spctl") > strings.Index(joined, "ditto") {
		t.Errorf("copy must come after the checks:\n%s", joined)
	}

	// Installing again refuses without --replace.
	if _, err := Install(context.Background(), InstallOptions{Dest: dest, Arch: "arm64", API: srv.URL + "/latest", HTTP: plainClient(srv), Run: &installRunner{}, Work: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Errorf("second install: %v", err)
	}
	if _, err := Install(context.Background(), InstallOptions{Dest: dest, Arch: "arm64", API: srv.URL + "/latest", HTTP: plainClient(srv), Run: &installRunner{}, Work: t.TempDir(), Replace: true}); err != nil {
		t.Errorf("replace: %v", err)
	}
	entries, _ := os.ReadDir(dest)
	if len(entries) != 1 || entries[0].Name() != "Clash Verge.app" {
		t.Errorf("after replace dest has %v", entries)
	}
}

func TestInstallRejectsAssetNamesWithPaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"tag_name": "v1", "assets": []map[string]any{
			{"name": "../escape_aarch64.dmg", "browser_download_url": "https://example.invalid/x", "size": 1},
		}})
	}))
	defer srv.Close()
	if _, err := LatestRelease(context.Background(), plainClient(srv), srv.URL+"/latest", "arm64"); err == nil || !strings.Contains(err.Error(), "plain file name") {
		t.Errorf("err = %v", err)
	}
}

func TestInstallRejectsUnsignedOrForeignApps(t *testing.T) {
	srv := releaseServer(t, []byte("dmg"))
	for _, tc := range []struct {
		name string
		r    *installRunner
		want string
	}{
		{"unsigned", &installRunner{rejectBy: "codesign"}, "not signed by Clash Verge Rev"},
		{"not notarized", &installRunner{rejectBy: "spctl"}, "Gatekeeper"},
		{"other app", &installRunner{bundleID: "com.example.other"}, "not Clash Verge Rev"},
	} {
		dest := t.TempDir()
		_, err := Install(context.Background(), InstallOptions{Dest: dest, Arch: "arm64", API: srv.URL + "/latest", HTTP: plainClient(srv), Run: tc.r, Work: t.TempDir()})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
		if strings.Contains(strings.Join(tc.r.calls, "\n"), "ditto") {
			t.Errorf("%s: copied anyway", tc.name)
		}
		if entries, _ := os.ReadDir(dest); len(entries) != 0 {
			t.Errorf("%s: dest not empty", tc.name)
		}
	}
}

func TestFindAppReadsVersion(t *testing.T) {
	r := &installRunner{}
	app, err := InspectApp(context.Background(), r, "/Applications/Clash Verge.app")
	if err != nil || app.Version != "2.5.8" || app.BundleID != BundleID || app.Label() != "Clash Verge 2.5.8" {
		t.Errorf("app = %+v, %v", app, err)
	}
	if _, err := InspectApp(context.Background(), &installRunner{bundleID: "x"}, "/Applications/X.app"); err == nil {
		t.Error("foreign bundle accepted")
	}
}
