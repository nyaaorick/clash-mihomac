// Command mihomac runs and controls Clash Mihomac, the companion to Clash
// Verge Rev.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/buildinfo"
	"github.com/nyaaorick/clash-mihomac/internal/daemon"
	"github.com/nyaaorick/clash-mihomac/internal/paths"
	"github.com/nyaaorick/clash-mihomac/internal/verge"
)

const usageText = `Usage: mihomac <command> [flags]

Clash Mihomac works alongside Clash Verge Rev: Verge runs mihomo, TUN, and
the system proxy; Clash Mihomac watches that core and adds diagnostics,
rules, server management, and an MCP server.

Running:
  up                One click: install Clash Verge if missing, start it, start the daemon, open the GUI
  start             Start the companion daemon and print the GUI address
  stop              Stop the daemon (Clash Verge keeps running)
  status            Show whether the daemon and Clash Verge's core are up
  verge             Clash Verge itself: status, install, open, restart (verge -h)
  webui             Print the GUI address; --install adds it to Clash Verge's Web UI list

Routing:
  rules             List rules; add, remove, or toggle packs (rules -h)
  groups            Failover groups: fallback, url-test, load-balance (groups -h)
  packs             Install, update, and remove community rule packs (packs -h)
  proposals         List, apply, or reject proposed rule changes

Diagnostics:
  connections       Recent connections (-q to filter)
  diagnose <id>     Explain where one connection went and why
  probe <url>       Compare a direct fetch with a proxied one
  interfaces        Network interfaces and the routes they own
  vps               Set up and manage proxy servers over SSH (vps -h)
  traffic           Physical traffic view: apps, NICs, surprises (traffic -h)
  health            Node health, blocking detection, and history (health -h)

Other:
  island            Run as the island4mac plugin (the daemon in-process, the tab on stdin/stdout)
  mcp               Run the MCP server on stdio (mcp --setup prints client setup)
  logs              Show the daemon's log, or Clash Verge's (--source verge)
  version           Print the Clash Mihomac version

Run "mihomac <command> -h" for a command's flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	commands := map[string]func([]string) error{
		"up": cmdUp, "start": cmdStart, "stop": cmdStop, "status": cmdStatus, "webui": cmdWebUI, "verge": cmdVerge,
		"rules": cmdRules, "proposals": cmdProposals,
		"connections": cmdConnections, "diagnose": cmdDiagnose, "probe": cmdProbe, "interfaces": cmdInterfaces,
		"mcp": cmdMCP, "packs": cmdPacks, "health": cmdHealth, "vps": cmdVPS, "traffic": cmdTraffic, "groups": cmdGroups, "logs": cmdLogs,
		"run":    cmdRun,    // internal: the daemon process started by `start`
		"island": cmdIsland, // the island4mac plugin: the daemon in-process, the tab over the plugin protocol
	}
	var err error
	switch {
	case cmd == "version":
		fmt.Printf("mihomac %s (%s build)\n", buildinfo.Version, buildinfo.Channel)
	case cmd == "help" || cmd == "-h" || cmd == "--help":
		fmt.Print(usageText)
	case commands[cmd] != nil:
		err = commands[cmd](args)
	default:
		fmt.Fprintf(os.Stderr, "mihomac: unknown command %q\n\n%s", cmd, usageText)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mihomac:", err)
		os.Exit(1)
	}
}

// resolve returns Clash Mihomac's data directory.
func resolve() (string, error) {
	return paths.Home()
}

func vergeDirFlag(fs *flag.FlagSet) *string {
	return fs.String("verge-dir", "", "Clash Verge Rev's data directory (default: its standard location, or MIHOMAC_VERGE_DIR)")
}

func locateVerge(flagValue string) (verge.Dir, error) {
	if flagValue != "" {
		os.Setenv("MIHOMAC_VERGE_DIR", flagValue)
	}
	return verge.Locate()
}

func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	port := fs.Int("gui-port", paths.GUIPort(), "port for the GUI and API on 127.0.0.1")
	vdir := vergeDirFlag(fs)
	fs.Parse(args)

	home, err := resolve()
	if err != nil {
		return err
	}
	vd, err := locateVerge(*vdir)
	if err != nil {
		return err
	}
	return startDaemon(home, vd, *port)
}

// startDaemon launches the daemon process and waits for its state file.
func startDaemon(home string, vd verge.Dir, port int) error {
	if st, ok, err := daemon.ReadState(home); err != nil {
		return err
	} else if ok {
		if daemon.IsRunning(st) {
			return fmt.Errorf("Clash Mihomac is already running (pid %d)", st.PID)
		}
		// A previous daemon died without cleaning up; clear what it left.
		if _, err := daemon.Stop(home, 5*time.Second); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	logPath := home + "/" + daemon.DaemonLog
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "run", "--gui-port", fmt.Sprint(port), "--verge-dir", string(vd))
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = cmd.Start()
	logFile.Close()
	if err != nil {
		return err
	}

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.After(30 * time.Second)
	for {
		if st, ok, _ := daemon.ReadState(home); ok && st.PID == cmd.Process.Pid {
			printRunning(home, st)
			return nil
		}
		select {
		case err := <-exited:
			return fmt.Errorf("daemon exited during startup (%v); last log lines:\n%s", err, tail(logPath, 8))
		case <-deadline:
			cmd.Process.Signal(syscall.SIGTERM)
			return fmt.Errorf("daemon did not become ready in time; see %s", logPath)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	port := fs.Int("gui-port", paths.GUIPort(), "GUI port")
	vdir := vergeDirFlag(fs)
	fs.Parse(args)

	home, err := resolve()
	if err != nil {
		return err
	}
	vd, err := locateVerge(*vdir)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return daemon.Run(ctx, daemon.Options{
		Home:    home,
		Verge:   vd,
		GUIPort: *port,
		Channel: buildinfo.Channel,
		Log:     log.New(os.Stderr, "", log.LstdFlags),
	})
}

func cmdStop(args []string) error {
	home, err := resolve()
	if err != nil {
		return err
	}
	stopped, err := daemon.Stop(home, 20*time.Second)
	if err != nil {
		return err
	}
	if stopped {
		fmt.Println("Stopped Clash Mihomac. Clash Verge and its core are untouched.")
	} else {
		fmt.Println("Clash Mihomac is not running.")
	}
	return nil
}

func cmdStatus(args []string) error {
	home, err := resolve()
	if err != nil {
		return err
	}
	st, ok, err := daemon.ReadState(home)
	if err != nil {
		return err
	}
	switch {
	case !ok:
		fmt.Println("Clash Mihomac is not running.")
	case !daemon.IsRunning(st):
		fmt.Printf("Clash Mihomac is not running (stale state from pid %d; `mihomac stop` cleans it up).\n", st.PID)
	default:
		printRunning(home, st)
		api, err := apiFor()
		if err != nil {
			return err
		}
		ctx, cancel := apiCtx()
		defer cancel()
		var s daemon.Status
		if err := api.Get(ctx, "/api/status", &s); err != nil {
			return err
		}
		v := s.Verge
		core := "unreachable"
		if v.MihomoVersion != "" {
			core = fmt.Sprintf("mihomo %s via %s, mode %s, mixed port %d", v.MihomoVersion, v.Controller, v.Mode, v.MixedPort)
		}
		tun := "off"
		if v.TUN {
			tun = "on (" + v.TUNDevice + ")"
		}
		app := "not running"
		if v.AppRunning {
			app = "running"
		}
		rulesState := "not active in the core"
		switch {
		case !s.HasRules:
			rulesState = "none of your own yet (add one with `mihomac rules add`)"
		case s.RulesActive:
			rulesState = "active in the core"
		case s.PendingRestart:
			rulesState = "saved; waiting for Clash Verge to restart"
		}
		fmt.Printf("  Clash Verge  %s\n  Core         %s\n  TUN          %s\n  Rules        %s\n", app, core, tun, rulesState)
		if v.ConfigError != "" {
			fmt.Printf("  Problem      %s\n", v.ConfigError)
		}
		for _, w := range s.Warnings {
			fmt.Println("  warning:", w)
		}
	}
	return nil
}

func cmdWebUI(args []string) error {
	fs := flag.NewFlagSet("webui", flag.ExitOnError)
	install := fs.Bool("install", false, "add the address to Clash Verge's Web UI list (Clash Verge must be closed)")
	vdir := vergeDirFlag(fs)
	fs.Parse(args)

	home, err := resolve()
	if err != nil {
		return err
	}
	url, err := guiURL(home)
	if err != nil {
		return err
	}
	// The address stored in Verge's settings carries no token: that file
	// is Verge's and world-readable. Opening the token URL once logs the
	// browser in for a year, after which the plain address works.
	plain := strings.SplitN(url, "?", 2)[0]
	if !*install {
		fmt.Println(url)
		fmt.Printf("\nOpen that once to log in; afterwards %s works on its own.\nAdd the plain address in Clash Verge under Settings → Web UI, or run `mihomac webui --install` while Clash Verge is closed.\n", plain)
		return nil
	}
	url = plain
	vd, err := locateVerge(*vdir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if verge.Running(ctx, execRunner{}) {
		return errors.New("quit Clash Verge first: it rewrites its settings file while running, so an entry added now would be lost")
	}
	changed, err := vd.AddWebUI(url)
	if err != nil {
		return err
	}
	if changed {
		fmt.Printf("Added %s to Clash Verge's Web UI list. Open the GUI once with `mihomac status` (that logs the browser in), then it opens from Clash Verge's Settings → Web UI.\n", url)
	} else {
		fmt.Println("Already in Clash Verge's Web UI list.")
	}
	return nil
}

// guiURL is the dashboard address with the login token, from the running
// daemon's state or, when it isn't running, the default port.
func guiURL(home string) (string, error) {
	tok, err := os.ReadFile(home + "/gui-token")
	if err != nil {
		return "", errors.New("no GUI token yet; run `mihomac start` once")
	}
	base := fmt.Sprintf("http://127.0.0.1:%d/", paths.GUIPort())
	if st, ok, _ := daemon.ReadState(home); ok && daemon.IsRunning(st) {
		base = st.GUIURL
	}
	return base + "?token=" + strings.TrimSpace(string(tok)), nil
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

func printRunning(home string, st daemon.State) {
	url, _ := guiURL(home)
	fmt.Printf(`Clash Mihomac is running (pid %d)
  Clash Verge  %s
  Data         %s
  GUI          %s
`, st.PID, st.VergeDir, home, url)
}

func tail(path string, n int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return "  " + strings.Join(lines, "\n  ")
}
