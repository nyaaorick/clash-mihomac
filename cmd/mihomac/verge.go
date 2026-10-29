package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/daemon"
	"github.com/nyaaorick/clash-mihomac/internal/paths"
	"github.com/nyaaorick/clash-mihomac/internal/verge"
)

const vergeUsage = `Usage:
  mihomac verge status               where Clash Verge is installed, its version, and whether it runs
  mihomac verge install [--replace]  download the latest Clash Verge Rev release and install it
  mihomac verge open                 start Clash Verge (or bring it to the front)
  mihomac verge restart              quit Clash Verge and start it again
  mihomac verge mode [rule|global|direct]   show or switch the core's mode (rules only apply in rule mode)

The installer takes the newest release from GitHub, checks the app's Apple
code signature and Gatekeeper assessment, and only then copies it to
/Applications (--into DIR for somewhere else).
`

func cmdVerge(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, vergeUsage)
		return errors.New("missing verge command")
	}
	sub := args[0]
	fs := flag.NewFlagSet("verge "+sub, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, vergeUsage) }
	replace := fs.Bool("replace", false, "install over an existing copy (Clash Verge must be closed)")
	into := fs.String("into", "/Applications", "directory to install into")
	fs.Parse(args[1:])
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	run := execRunner{}

	switch sub {
	case "status":
		app, err := verge.FindApp(ctx, run)
		if err != nil {
			fmt.Println(err)
			fmt.Println("Install it with `mihomac verge install`.")
			return nil
		}
		printApp(app)
		if verge.Running(ctx, run) {
			fmt.Println("  State        running")
		} else {
			fmt.Println("  State        not running")
		}
		if vd, err := verge.Locate(); err == nil {
			fmt.Println("  Data         " + string(vd))
			if rt, err := vd.ReadRuntime(); err == nil {
				ep, _ := rt.Endpoint()
				fmt.Printf("  Controller   %s\n  TUN          %v (%s)\n", ep, rt.TUN, rt.TUNDevice)
			}
		} else {
			fmt.Println("  Data         none yet (Clash Verge hasn't run)")
		}
		return nil
	case "install":
		app, err := installVerge(ctx, run, *into, *replace)
		if err != nil {
			return err
		}
		printApp(app)
		return nil
	case "open":
		app, err := verge.FindApp(ctx, run)
		if err != nil {
			return err
		}
		return app.Open(ctx, run)
	case "restart":
		if err := verge.Restart(ctx, run); err != nil {
			return err
		}
		fmt.Println("Clash Verge restarted.")
		return nil
	case "mode":
		api, err := apiFor()
		if err != nil {
			return err
		}
		var st daemon.Status
		if fs.NArg() == 0 {
			if err := api.Get(ctx, "/api/status", &st); err != nil {
				return err
			}
			fmt.Println(st.Verge.Mode)
			if st.Verge.Mode != "rule" {
				fmt.Println("Rules only apply in rule mode: `mihomac verge mode rule`.")
			}
			return nil
		}
		if err := api.Post(ctx, "/api/verge/mode", map[string]string{"mode": fs.Arg(0)}, &st); err != nil {
			return err
		}
		fmt.Printf("Core is now in %s mode. Clash Verge keeps its own setting; switch it there too if you want this to survive a Clash Verge restart.\n", st.Verge.Mode)
		return nil
	}
	fmt.Fprint(os.Stderr, vergeUsage)
	return fmt.Errorf("unknown verge command %q", sub)
}

func installVerge(ctx context.Context, run verge.Runner, into string, replace bool) (verge.App, error) {
	fmt.Println("Looking up the latest Clash Verge Rev release…")
	var lastPct int64 = -1
	app, err := verge.Install(ctx, verge.InstallOptions{
		Dest: into, Run: run, Replace: replace,
		Progress: func(done, total int64) {
			if total <= 0 {
				return
			}
			if pct := done * 100 / total; pct/5 != lastPct/5 {
				lastPct = pct
				fmt.Printf("\r  downloading… %3d%% (%d / %d MB)", pct, done>>20, total>>20)
			}
		},
	})
	fmt.Println()
	if err != nil {
		return verge.App{}, err
	}
	fmt.Printf("Installed %s at %s.\n", app.Label(), app.Path)
	return app, nil
}

func printApp(app verge.App) {
	service := "not installed (Clash Verge asks for it on first start; TUN needs it)"
	if app.Service {
		service = "installed"
	}
	fmt.Printf("%s\n  App          %s\n  Service      %s\n", app.Label(), app.Path, service)
}

// cmdUp is the one-click start: Clash Verge installed and running, the
// daemon up, the GUI open.
func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	port := fs.Int("gui-port", paths.GUIPort(), "port for the GUI and API on 127.0.0.1")
	noOpen := fs.Bool("no-open", false, "don't open the GUI in the browser")
	fs.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	run := execRunner{}

	app, err := verge.FindApp(ctx, run)
	if errors.Is(err, verge.ErrNotInstalled) {
		fmt.Println("Clash Verge is not installed yet.")
		if app, err = installVerge(ctx, run, "/Applications", false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	fmt.Printf("%s at %s\n", app.Label(), app.Path)

	plainURL := fmt.Sprintf("http://127.0.0.1:%d/", *port)
	if !verge.Running(ctx, run) {
		// Verge reads its settings at start and rewrites them later, so
		// this is the moment to add the dashboard to its Web UI list.
		if vd, err := verge.Locate(); err == nil {
			if changed, err := vd.AddWebUI(plainURL); err != nil {
				fmt.Println("Couldn't add the GUI to Clash Verge's Web UI list:", err)
			} else if changed {
				fmt.Println("Added the GUI to Clash Verge's Web UI list (Settings → Web UI).")
			}
		}
		fmt.Println("Starting Clash Verge…")
		if err := app.Open(ctx, run); err != nil {
			return err
		}
	} else if vd, err := verge.Locate(); err == nil {
		if st, err := vd.ReadSettings(); err == nil && !hasWebUI(st.WebUIList, plainURL) {
			fmt.Println("The GUI isn't in Clash Verge's Web UI list yet; it is added the next time `mihomac up` starts Clash Verge (or run `mihomac webui --install` with Clash Verge closed).")
		}
	}
	vd, err := waitForVerge(ctx, 90*time.Second)
	if err != nil {
		return err
	}
	if !app.Service {
		fmt.Println("Note: Clash Verge's system service isn't installed; TUN mode needs it. Clash Verge offers to install it in Settings → System Service.")
	}

	home, err := resolve()
	if err != nil {
		return err
	}
	if st, ok, _ := daemon.ReadState(home); ok && daemon.IsRunning(st) {
		fmt.Println("Clash Mihomac is already running.")
		printRunning(home, st)
	} else if err := startDaemon(home, vd, *port); err != nil {
		return err
	}
	if *noOpen {
		return nil
	}
	url, err := guiURL(home)
	if err != nil {
		return err
	}
	return exec.Command("/usr/bin/open", url).Run()
}

// waitForVerge waits until Clash Verge has written its runtime config and
// its controller socket exists (a first run takes a while: Verge creates
// its data directory and may ask the user to install its service).
func waitForVerge(ctx context.Context, timeout time.Duration) (verge.Dir, error) {
	deadline := time.Now().Add(timeout)
	said := false
	for {
		vd, err := verge.Locate()
		if err == nil {
			if rt, err := vd.ReadRuntime(); err == nil {
				if ep, err := rt.Endpoint(); err == nil {
					if ep.Network != "unix" {
						return vd, nil
					}
					if _, err := os.Stat(ep.Address); err == nil {
						return vd, nil
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return "", errors.New("Clash Verge's core didn't come up in time (if this is its first run, finish its setup, then run `mihomac up` again)")
		}
		if !said {
			fmt.Println("Waiting for Clash Verge's core…")
			said = true
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func hasWebUI(list []string, url string) bool {
	for _, u := range list {
		if u == url {
			return true
		}
	}
	return false
}
