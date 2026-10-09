// Command mihomac controls Clash Mihomac instances.
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
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/buildinfo"
	"github.com/nyaaorick/clash-mihomac/internal/core"
	"github.com/nyaaorick/clash-mihomac/internal/daemon"
	"github.com/nyaaorick/clash-mihomac/internal/helper"
	"github.com/nyaaorick/clash-mihomac/internal/instance"
	"github.com/nyaaorick/clash-mihomac/internal/runtimecfg"
)

const usageText = `Usage: mihomac <command> [flags]

Running:
  start             Start an instance (--mode tun | system-proxy | port-only)
  stop              Stop an instance and restore the network
  status            Show an instance's status and GUI URL
  mode <mode>       Switch a running instance's mode
  restore-network   Stop every instance and restore routes, DNS, and proxy settings

Routing:
  rules             List rules; add, remove, or toggle packs (rules -h)
  packs             Install, update, and remove community rule packs (packs -h)
  proposals         List, apply, or reject proposed rule changes

Diagnostics:
  connections       Recent connections (-q to filter)
  diagnose <id>     Explain where one connection went and why
  probe <url>       Compare a direct fetch with a proxied one
  interfaces        Network interfaces and the routes they own

Other:
  mcp               Run the MCP server on stdio (mcp --setup prints client setup)
  profile           Add, list, or remove side-by-side profiles (profile -h)
  core              Manage mihomo versions: install, list, use, rollback, remove
  logs              Show an instance's daemon or core log
  helper <cmd>      Talk to the privileged helper: ping, status, snapshot
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
		"start": cmdStart, "stop": cmdStop, "status": cmdStatus, "mode": cmdMode,
		"restore-network": cmdRestoreNetwork,
		"rules":           cmdRules, "proposals": cmdProposals,
		"connections": cmdConnections, "diagnose": cmdDiagnose, "probe": cmdProbe, "interfaces": cmdInterfaces,
		"mcp": cmdMCP, "core": cmdCore, "helper": cmdHelper, "profile": cmdProfile, "packs": cmdPacks, "logs": cmdLogs,
		"run":       cmdRun,      // internal: the daemon process started by `start`
		"core-exec": cmdCoreExec, // internal: wrapper that ties mihomo to the daemon
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

func instanceFlag(fs *flag.FlagSet) *string {
	return fs.String("instance", buildinfo.Channel, "instance to use ("+strings.Join(instance.Names(), ", ")+")")
}

func helperSocketFlag(fs *flag.FlagSet) *string {
	def := helper.DefaultSocket
	if s := os.Getenv("MIHOMAC_HELPER_SOCKET"); s != "" {
		def = s
	}
	return fs.String("helper-socket", def, "privileged helper socket (env MIHOMAC_HELPER_SOCKET)")
}

func resolve(name string) (string, instance.Instance, error) {
	home, err := instance.Home()
	if err != nil {
		return "", instance.Instance{}, err
	}
	inst, err := instance.Get(home, name)
	return home, inst, err
}

func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	name := instanceFlag(fs)
	config := fs.String("config", "", "mihomo config file (default <instance dir>/config.yaml)")
	coreVersion := fs.String("core", "", "mihomo core version (default: the instance's selected version, see `mihomac core use`)")
	mode := fs.String("mode", "", "tun, system-proxy, or port-only (default: tun for stable, port-only for debug)")
	routeAddr := fs.String("route-address", "", "comma-separated CIDRs: only capture these in TUN mode (for testing)")
	socket := helperSocketFlag(fs)
	fs.Parse(args)

	home, inst, err := resolve(*name)
	if err != nil {
		return err
	}
	if *coreVersion == "" {
		*coreVersion = core.Selected(inst.Dir, core.DefaultVersion)
	}
	if *mode == "" {
		*mode = runtimecfg.ModePortOnly
		if inst.TUNDefault {
			*mode = runtimecfg.ModeTUN
		}
	}
	if !slices.Contains(runtimecfg.Modes, *mode) {
		return fmt.Errorf("unknown mode %q (want one of %v)", *mode, runtimecfg.Modes)
	}
	if st, ok, err := daemon.ReadState(inst); err != nil {
		return err
	} else if ok {
		if daemon.IsRunning(st) {
			return fmt.Errorf("instance %s is already running (pid %d)", inst.Name, st.PID)
		}
		// A previous daemon died without cleaning up; clear what it left.
		if _, err := daemon.Stop(inst, 5*time.Second); err != nil {
			return err
		}
	}
	if *mode != runtimecfg.ModePortOnly {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := helper.Call(ctx, *socket, "ping", nil, nil)
		cancel()
		if err != nil {
			return fmt.Errorf("%s mode needs the privileged helper: %w\nInstall it with `sudo make install-helper`, or start with --mode port-only", *mode, err)
		}
	}

	cfgPath := *config
	if cfgPath == "" {
		cfgPath = inst.Path("config.yaml")
	}
	cfgPath, err = filepath.Abs(cfgPath)
	if err != nil {
		return err
	}
	user, err := os.ReadFile(cfgPath)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("config %s not found; pass --config or copy examples/config.example.yaml there", cfgPath)
	} else if err != nil {
		return err
	}
	res, err := runtimecfg.Build(user, runtimecfg.Options{
		MixedPort: inst.MixedPort, ControllerPort: inst.ControllerPort, Mode: *mode, TUNDevice: inst.TUNDevice, TUNAddress: inst.TUNAddress,
	})
	if err != nil {
		return err
	}
	for _, w := range res.Warnings {
		fmt.Println("warning:", w)
	}

	mgr := core.NewManager(home)
	if !mgr.IsInstalled(*coreVersion) {
		fmt.Printf("Installing mihomo %s…\n", *coreVersion)
		if _, err := mgr.Install(context.Background(), *coreVersion, runtime.GOARCH, ""); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(inst.Dir, 0o700); err != nil {
		return err
	}
	logPath := inst.Path("daemon.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	runArgs := []string{"run", "--instance", inst.Name, "--config", cfgPath, "--core", *coreVersion, "--mode", *mode, "--helper-socket", *socket}
	if *routeAddr != "" {
		runArgs = append(runArgs, "--route-address", *routeAddr)
	}
	cmd := exec.Command(exe, runArgs...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = cmd.Start()
	logFile.Close()
	if err != nil {
		return err
	}

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.After(45 * time.Second)
	for {
		if st, ok, _ := daemon.ReadState(inst); ok && st.PID == cmd.Process.Pid {
			printRunning(inst, st)
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
	name := instanceFlag(fs)
	config := fs.String("config", "", "mihomo config file")
	coreVersion := fs.String("core", core.DefaultVersion, "mihomo core version")
	mode := fs.String("mode", runtimecfg.ModePortOnly, "mode")
	routeAddr := fs.String("route-address", "", "comma-separated CIDRs to capture in TUN mode")
	socket := helperSocketFlag(fs)
	fs.Parse(args)

	home, inst, err := resolve(*name)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var routes []string
	if *routeAddr != "" {
		routes = strings.Split(*routeAddr, ",")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return daemon.Run(ctx, daemon.Options{
		Instance:     inst,
		Channel:      buildinfo.Channel,
		CorePath:     core.NewManager(home).BinaryPath(*coreVersion),
		CoreVersion:  *coreVersion,
		ConfigPath:   *config,
		Mode:         *mode,
		RouteAddress: routes,
		HelperSocket: *socket,
		Exe:          exe,
		Log:          log.New(os.Stderr, "", log.LstdFlags),
	})
}

func cmdCoreExec(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: mihomac core-exec <core> [args...]")
	}
	return daemon.Supervise(args[0], args[1:])
}

func cmdStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	name := instanceFlag(fs)
	fs.Parse(args)

	_, inst, err := resolve(*name)
	if err != nil {
		return err
	}
	stopped, err := daemon.Stop(inst, 40*time.Second)
	if err != nil {
		return err
	}
	if stopped {
		fmt.Printf("Stopped %s.\n", inst.Name)
	} else {
		fmt.Printf("%s is not running.\n", inst.Name)
	}
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	name := instanceFlag(fs)
	fs.Parse(args)

	_, inst, err := resolve(*name)
	if err != nil {
		return err
	}
	st, ok, err := daemon.ReadState(inst)
	if err != nil {
		return err
	}
	switch {
	case !ok:
		fmt.Printf("%s is not running.\n", inst.Name)
	case !daemon.IsRunning(st):
		fmt.Printf("%s is not running (stale state from pid %d; `mihomac stop --instance %s` cleans it up).\n", inst.Name, st.PID, inst.Name)
	default:
		printRunning(inst, st)
	}
	return nil
}

func cmdRestoreNetwork(args []string) error {
	fs := flag.NewFlagSet("restore-network", flag.ExitOnError)
	socket := helperSocketFlag(fs)
	fs.Parse(args)

	home, err := instance.Home()
	if err != nil {
		return err
	}
	insts, err := instance.List(home)
	if err != nil {
		return err
	}
	for _, inst := range insts {
		stopped, err := daemon.Stop(inst, 40*time.Second)
		if err != nil {
			return fmt.Errorf("stop %s: %w", inst.Name, err)
		}
		if stopped {
			fmt.Printf("Stopped %s.\n", inst.Name)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var res helper.RestoreResult
	if err := helper.Call(ctx, *socket, "restore-network", nil, &res); err != nil {
		fmt.Printf("The privileged helper isn't reachable (%v).\nWithout it Clash Mihomac can only run in port-only mode, which never changes routes, DNS, or proxy settings.\n", err)
		return nil
	}
	for _, ev := range res.Ended {
		fmt.Printf("[%s] %s\n", ev.Instance, ev.Message)
	}
	switch {
	case res.Network == nil:
		fmt.Println("Network settings already match their pre-Clash-Mihomac state.")
	case res.Network.OK():
		for _, a := range res.Network.Actions {
			fmt.Println("  " + a)
		}
		fmt.Println("Network settings restored and verified.")
	default:
		for _, r := range res.Network.Remaining {
			fmt.Println("  still different: " + r)
		}
		return errors.New("network not fully restored; see above")
	}
	return nil
}

func cmdHelper(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: mihomac helper <ping|status|snapshot>")
	}
	fs := flag.NewFlagSet("helper", flag.ExitOnError)
	socket := helperSocketFlag(fs)
	fs.Parse(args[1:])

	cmds := map[string]string{"ping": "ping", "status": "status", "snapshot": "network-snapshot"}
	cmd, ok := cmds[args[0]]
	if !ok {
		return fmt.Errorf("unknown helper command %q", args[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var res any
	if err := helper.Call(ctx, *socket, cmd, nil, &res); err != nil {
		return err
	}
	return printJSON(res)
}

func printRunning(inst instance.Instance, st daemon.State) {
	url := st.GUIURL
	if tok, err := os.ReadFile(inst.Path("gui-token")); err == nil {
		url += "?token=" + strings.TrimSpace(string(tok))
	}
	modeDesc := map[string]string{
		runtimecfg.ModeTUN:         "TUN: traffic captured on " + inst.TUNDevice,
		runtimecfg.ModeSystemProxy: fmt.Sprintf("system proxy: apps that honor it use 127.0.0.1:%d", st.MixedPort),
		runtimecfg.ModePortOnly:    "port-only: routes, DNS, and proxy settings untouched",
	}[st.Mode]
	fmt.Printf(`%s is running (pid %d)
  Mode    %s
  Proxy   http/socks5 127.0.0.1:%d
  Core    mihomo %s
  Config  %s
  GUI     %s

Try it:   curl -x http://127.0.0.1:%d -I https://example.com
`, inst.Name, st.PID, modeDesc, st.MixedPort, st.CoreVersion, st.ConfigPath, url, st.MixedPort)
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
