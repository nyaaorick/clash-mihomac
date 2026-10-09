package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/nyaaorick/clash-mihomac/internal/core"
	"github.com/nyaaorick/clash-mihomac/internal/daemon"
	"github.com/nyaaorick/clash-mihomac/internal/instance"
)

const profileUsage = `Usage:
  mihomac profile list                 every instance and profile, with ports and status
  mihomac profile add <label>          create a profile (p1, p2, ...) with its own ports,
                                       directory, TUN device, and mihomo version
  mihomac profile remove <name>        delete a stopped profile and its data

Profiles run side by side with stable and debug: start one with
  mihomac start --instance p1 --config <file>
`

func cmdProfile(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, profileUsage)
		return errors.New("missing profile command")
	}
	home, err := instance.Home()
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		infos, err := daemon.ListInstances(home, "")
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tLABEL\tSTATUS\tMODE\tCORE\tMIXED\tGUI\tTUN")
		for _, i := range infos {
			status := "stopped"
			if i.Running {
				status = fmt.Sprintf("running (pid %d)", i.PID)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n", i.Name, i.Label, status, orDash(i.Mode), i.CoreVersion, i.MixedPort, i.GUIPort, i.TUNDevice)
		}
		return w.Flush()
	case "add":
		if len(args) != 2 {
			return errors.New("usage: mihomac profile add <label>")
		}
		inst, err := instance.Create(home, args[1])
		if err != nil {
			return err
		}
		fmt.Printf("Created profile %s (%s): proxy port %d, GUI port %d, TUN %s.\nStart it with: mihomac start --instance %s --config <file>\n",
			inst.Name, inst.Label(), inst.MixedPort, inst.GUIPort, inst.TUNDevice, inst.Name)
		return nil
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: mihomac profile remove <name>")
		}
		inst, err := instance.Get(home, args[1])
		if err != nil {
			return err
		}
		if st, ok, _ := daemon.ReadState(inst); ok && daemon.IsRunning(st) {
			return fmt.Errorf("%s is running; stop it first with `mihomac stop --instance %s`", inst.Name, inst.Name)
		}
		if err := instance.Remove(home, inst.Name); err != nil {
			return err
		}
		fmt.Printf("Removed profile %s.\n", inst.Name)
		return nil
	}
	fmt.Fprint(os.Stderr, profileUsage)
	return fmt.Errorf("unknown profile command %q", args[0])
}

const coreUsage = `Usage:
  mihomac core install [--version vX.Y.Z] [--sha256 HEX]
  mihomac core list [--instance NAME]      installed versions; marks what an instance uses
  mihomac core use <vX.Y.Z> [--instance NAME]      switch an instance to an installed version
  mihomac core rollback [--instance NAME]          switch back to the previous version
  mihomac core remove <vX.Y.Z>             delete an installed version nothing is using

A running instance picks up a new version the next time it starts.
`

func cmdCore(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, coreUsage)
		return errors.New("missing core command")
	}
	home, err := instance.Home()
	if err != nil {
		return err
	}
	mgr := core.NewManager(home)

	fs := flag.NewFlagSet("core "+args[0], flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, coreUsage) }
	name := instanceFlag(fs)
	version := fs.String("version", core.DefaultVersion, "mihomo version (vX.Y.Z)")
	sum := fs.String("sha256", "", "SHA-256 of the release asset (required for versions without a pinned checksum)")
	// Let the version come before or after the flags: `core use v1.2.3 --instance p1`.
	var positional []string
	rest := args[1:]
	for len(rest) > 0 {
		fs.Parse(rest)
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	inst, err := instance.Get(home, *name)
	if err != nil {
		return err
	}
	current := core.Selected(inst.Dir, core.DefaultVersion)

	switch args[0] {
	case "install":
		path, err := mgr.Install(context.Background(), *version, runtime.GOARCH, *sum)
		if err != nil {
			return err
		}
		fmt.Printf("Installed mihomo %s at %s\n", *version, path)
	case "list":
		versions, err := mgr.Installed()
		if err != nil {
			return err
		}
		if len(versions) == 0 {
			fmt.Println("No cores installed. Run `mihomac core install`.")
		}
		for _, v := range versions {
			var marks []string
			if v == core.DefaultVersion {
				marks = append(marks, "default")
			}
			if v == current {
				marks = append(marks, "used by "+inst.Name)
			}
			if len(marks) > 0 {
				v += " (" + strings.Join(marks, ", ") + ")"
			}
			fmt.Println(v)
		}
	case "use":
		if len(positional) != 1 {
			return errors.New("usage: mihomac core use <vX.Y.Z> [--instance NAME]")
		}
		if err := mgr.Select(inst.Dir, current, positional[0]); err != nil {
			return err
		}
		fmt.Printf("%s will use mihomo %s%s.\n", inst.Name, positional[0], restartNote(inst))
	case "rollback":
		v, err := mgr.Rollback(inst.Dir, current)
		if err != nil {
			return err
		}
		fmt.Printf("%s rolled back to mihomo %s%s.\n", inst.Name, v, restartNote(inst))
	case "remove":
		if len(positional) != 1 {
			return errors.New("usage: mihomac core remove <vX.Y.Z>")
		}
		if user := coreInUse(home, positional[0]); user != "" {
			return fmt.Errorf("mihomo %s is in use by %s; switch it to another version first", positional[0], user)
		}
		if err := mgr.Remove(positional[0]); err != nil {
			return err
		}
		fmt.Printf("Removed mihomo %s.\n", positional[0])
	default:
		fmt.Fprint(os.Stderr, coreUsage)
		return fmt.Errorf("unknown core command %q", args[0])
	}
	return nil
}

// restartNote reminds the user that a running instance keeps its old core
// until restarted.
func restartNote(inst instance.Instance) string {
	if st, ok, _ := daemon.ReadState(inst); ok && daemon.IsRunning(st) {
		return fmt.Sprintf(" once restarted (`mihomac stop --instance %s && mihomac start --instance %s`)", inst.Name, inst.Name)
	}
	return ""
}

// coreInUse names an instance that is running or is set to use version.
func coreInUse(home, version string) string {
	insts, _ := instance.List(home)
	for _, inst := range insts {
		if st, ok, _ := daemon.ReadState(inst); ok && daemon.IsRunning(st) && st.CoreVersion == version {
			return inst.Name + " (running)"
		}
		if core.Selected(inst.Dir, "") == version {
			return inst.Name
		}
	}
	return ""
}

func cmdLogs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	name := instanceFlag(fs)
	source := fs.String("source", "daemon", "daemon or core")
	lines := fs.Int("n", 100, "number of lines")
	fs.Parse(args)
	_, inst, err := resolve(*name)
	if err != nil {
		return err
	}
	out, err := daemon.ReadLog(inst, *source, *lines)
	if err != nil {
		return err
	}
	if len(out) == 0 {
		fmt.Printf("No %s log for %s yet.\n", *source, inst.Name)
	}
	for _, l := range out {
		fmt.Println(l)
	}
	return nil
}
