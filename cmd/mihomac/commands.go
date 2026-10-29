package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/buildinfo"
	"github.com/nyaaorick/clash-mihomac/internal/client"
	"github.com/nyaaorick/clash-mihomac/internal/daemon"
	"github.com/nyaaorick/clash-mihomac/internal/mcp"
	"github.com/nyaaorick/clash-mihomac/internal/rules"
)

// apiFor returns a full-scope client for the running daemon.
func apiFor() (*client.Client, error) {
	home, err := resolve()
	if err != nil {
		return nil, err
	}
	if !running(home) {
		return nil, client.ErrNotRunning
	}
	return client.Connect(home, client.TokenFull)
}

func running(home string) bool {
	st, ok, _ := daemon.ReadState(home)
	return ok && daemon.IsRunning(st)
}

func apiCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 90*time.Second)
}

const rulesUsage = `Usage:
  mihomac rules [list]                                    final rule list with sources
  mihomac rules add --type T --value V --target X [--note N]
  mihomac rules remove --type T --value V --target X
  mihomac rules packs [--enable NAME] [--disable NAME]
  mihomac rules app <App name or bundle id>               print the .app path for an "app" rule

Types: domain, domain-suffix, domain-keyword, ip-cidr, process-name, process-path, app
Targets: DIRECT, REJECT, a proxy or group from your config, or iface:<name> (e.g. iface:en1)

Changes are written to Clash Verge's global Merge profile and hot-loaded into its
running core; while the daemon is stopped they are saved and applied at the next start.
`

func cmdRules(args []string) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("rules "+sub, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, rulesUsage) }
	typ := fs.String("type", "", "rule type")
	value := fs.String("value", "", "rule value")
	target := fs.String("target", "", "rule target")
	note := fs.String("note", "", "note shown in diagnostics")
	enable := fs.String("enable", "", "pack to enable")
	disable := fs.String("disable", "", "pack to disable")
	fs.Parse(args)

	home, err := resolve()
	if err != nil {
		return err
	}
	var change rules.Change
	switch sub {
	case "list":
		return listRules(home)
	case "add":
		change.Add = []rules.Rule{{Type: *typ, Value: *value, Target: *target, Note: *note}}
	case "remove":
		change.Remove = []rules.Rule{{Type: *typ, Value: *value, Target: *target}}
	case "packs":
		if *enable == "" && *disable == "" {
			set, _ := rules.Load(filepath.Join(home, "rules.yaml"))
			all := set.AllPacks()
			for _, p := range set.PackNames() {
				mark := " "
				if slices.Contains(set.Packs, p) {
					mark = "✓"
				}
				fmt.Printf("%s %-16s %s\n", mark, p, all[p].Description)
			}
			return nil
		}
		if *enable != "" {
			change.EnablePacks = []string{*enable}
		}
		if *disable != "" {
			change.DisablePacks = []string{*disable}
		}
	case "app":
		if fs.NArg() != 1 {
			return errors.New("usage: mihomac rules app <App name or bundle id>")
		}
		path, err := findApp(fs.Arg(0))
		if err != nil {
			return err
		}
		fmt.Println(path)
		return nil
	default:
		fmt.Fprint(os.Stderr, rulesUsage)
		return fmt.Errorf("unknown rules command %q", sub)
	}
	return changeRules(home, change)
}

func listRules(home string) error {
	if !running(home) {
		set, err := rules.Load(filepath.Join(home, "rules.yaml"))
		if err != nil {
			return err
		}
		fmt.Println("Clash Mihomac is not running; your rules (applied on start, ahead of the built-in bypass):")
		for i, r := range set.Rules {
			fmt.Printf("  #%d  %s  %s\n", i+1, rules.Describe(r), r.Note)
		}
		fmt.Printf("Packs: %v\n", set.Packs)
		return nil
	}
	api, err := client.Connect(home, client.TokenFull)
	if err != nil {
		return err
	}
	ctx, cancel := apiCtx()
	defer cancel()
	var v daemon.RulesView
	if err := api.Get(ctx, "/api/rules", &v); err != nil {
		return err
	}
	if len(v.Compiled) == 0 {
		fmt.Println("Clash Verge's core isn't reachable, so the final rule list is unknown. Your rules (ahead of the built-in bypass once applied):")
		for i, r := range v.Set.Rules {
			fmt.Printf("  #%d  %s  %s\n", i+1, rules.Describe(r), r.Note)
		}
		fmt.Printf("Packs: %v\n", v.Set.Packs)
		return nil
	}
	if !v.Active && len(v.Set.Rules) > 0 {
		fmt.Println("Note: the running core does not have your rules at the front of its list; see `mihomac status`.")
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "#\tRULE\tSOURCE")
	for _, r := range v.Compiled {
		src := r.Source.Kind
		switch r.Source.Kind {
		case "user":
			src = "user " + r.Source.Name
		case "pack":
			src = "pack " + r.Source.Name
		case "config":
			src = fmt.Sprintf("Verge profile #%d", r.Source.Index)
		}
		if r.Source.Note != "" {
			src += " (" + r.Source.Note + ")"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\n", r.Position, r.Line, src)
	}
	return w.Flush()
}

func changeRules(home string, change rules.Change) error {
	if running(home) {
		api, err := client.Connect(home, client.TokenFull)
		if err != nil {
			return err
		}
		ctx, cancel := apiCtx()
		defer cancel()
		var v daemon.RulesView
		if err := api.Post(ctx, "/api/rules/change", change, &v); err != nil {
			return err
		}
		if v.Active {
			fmt.Println("Applied: written to Clash Verge's merge profile and loaded into the running core.")
		} else {
			fmt.Println("Saved to Clash Verge's merge profile; it applies when Clash Verge (re)starts. `mihomac status` shows why the core didn't take it now.")
		}
		return nil
	}
	path := filepath.Join(home, "rules.yaml")
	set, err := rules.Load(path)
	if err != nil {
		return err
	}
	diff, err := set.Diff(change)
	if err != nil {
		return err
	}
	next, _ := set.Apply(change)
	if err := rules.Save(path, next); err != nil {
		return err
	}
	fmt.Print(diff)
	fmt.Printf("Saved to %s; applied when Clash Mihomac starts.\n", path)
	return nil
}

// findApp resolves an app name or bundle ID to an .app path.
func findApp(q string) (string, error) {
	if strings.HasSuffix(q, ".app") && filepath.IsAbs(q) {
		return q, nil
	}
	home, _ := os.UserHomeDir()
	for _, dir := range []string{"/Applications", "/Applications/Utilities", "/System/Applications", filepath.Join(home, "Applications")} {
		p := filepath.Join(dir, strings.TrimSuffix(q, ".app")+".app")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	out, err := exec.Command("/usr/bin/mdfind", "kMDItemCFBundleIdentifier == '"+strings.ReplaceAll(q, "'", "")+"'").Output()
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if strings.HasSuffix(line, ".app") {
				return line, nil
			}
		}
	}
	return "", fmt.Errorf("no app named or with bundle ID %q", q)
}

func cmdProposals(args []string) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("proposals "+sub, flag.ExitOnError)
	fs.Parse(args)
	api, err := apiFor()
	if err != nil {
		return err
	}
	ctx, cancel := apiCtx()
	defer cancel()

	switch sub {
	case "list":
		var ps []daemon.Proposal
		if err := api.Get(ctx, "/api/proposals", &ps); err != nil {
			return err
		}
		if len(ps) == 0 {
			fmt.Println("No proposals.")
		}
		for _, p := range ps {
			fmt.Printf("%s  %-8s  from %-5s  %s  %s\n", p.ID, p.Status, p.Origin, p.Created.Format("2006-01-02 15:04"), p.Summary)
			if p.Status == daemon.StatusPending {
				fmt.Print(indentLines(p.Diff, "    "))
			}
		}
		return nil
	case "apply", "reject":
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: mihomac proposals %s <id>", sub)
		}
		var p daemon.Proposal
		if err := api.Post(ctx, "/api/proposals/"+url.PathEscape(fs.Arg(0))+"/"+sub, nil, &p); err != nil {
			return err
		}
		fmt.Printf("Proposal %s %s.\n", p.ID, p.Status)
		return nil
	}
	return fmt.Errorf("unknown proposals command %q (list, apply, reject)", sub)
}

func cmdConnections(args []string) error {
	fs := flag.NewFlagSet("connections", flag.ExitOnError)
	q := fs.String("q", "", "filter by host, IP, app, rule, or node")
	n := fs.Int("n", 30, "how many to show")
	fs.Parse(args)
	api, err := apiFor()
	if err != nil {
		return err
	}
	ctx, cancel := apiCtx()
	defer cancel()
	var conns []daemon.Conn
	if err := api.Get(ctx, "/api/connections?q="+url.QueryEscape(*q)+"&limit="+strconv.Itoa(*n), &conns); err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTIME\tAPP\tDESTINATION\tRULE\tROUTE\tSTATE")
	for _, cn := range conns {
		state := "open"
		if cn.End != nil {
			state = "closed"
		}
		rule := cn.Rule
		if cn.RulePayload != "" {
			rule += "," + cn.RulePayload
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", cn.ID[:min(8, len(cn.ID))], cn.Start.Format("15:04:05"), orDash(cn.Process),
			cn.Destination(), rule, strings.Join(cn.Chains, " ← "), state)
	}
	w.Flush()
	fmt.Println("\n`mihomac diagnose <ID>` explains one connection.")
	return nil
}

func cmdDiagnose(args []string) error {
	fs := flag.NewFlagSet("diagnose", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: mihomac diagnose <connection ID or ID prefix>")
	}
	api, err := apiFor()
	if err != nil {
		return err
	}
	ctx, cancel := apiCtx()
	defer cancel()

	id := strings.TrimSpace(fs.Arg(0))
	if id == "" {
		return errors.New("usage: mihomac diagnose <connection ID or ID prefix>")
	}
	if len(id) < 36 { // expand a prefix from `connections`
		var conns []daemon.Conn
		if err := api.Get(ctx, "/api/connections?limit=1000", &conns); err != nil {
			return err
		}
		i := slices.IndexFunc(conns, func(cn daemon.Conn) bool { return strings.HasPrefix(cn.ID, id) })
		if i < 0 {
			return fmt.Errorf("no recent connection with ID %q; run `mihomac connections`", id)
		}
		id = conns[i].ID
	}
	var d daemon.ConnectionDetail
	if err := api.Get(ctx, "/api/connections/"+url.PathEscape(id), &d); err != nil {
		return err
	}
	fmt.Println(d.Explanation.Summary)
	fmt.Println()
	for i, s := range d.Explanation.Path {
		arrow := "  "
		if i > 0 {
			arrow = "→ "
		}
		line := fmt.Sprintf("%s%-12s %s", arrow, s.Kind, s.Label)
		if s.Detail != "" {
			line += "  (" + s.Detail + ")"
		}
		fmt.Println(line)
	}
	cn := d.Conn
	fmt.Printf("\nStarted %s, %s up / %s down", cn.Start.Format(time.TimeOnly), byteSize(cn.Upload), byteSize(cn.Download))
	if cn.End != nil {
		fmt.Printf(", closed after %s", cn.End.Sub(cn.Start).Round(time.Millisecond))
	}
	fmt.Println()
	if len(d.Logs) > 0 {
		fmt.Println("\nCore log lines mentioning this destination:")
		for _, l := range d.Logs {
			fmt.Printf("  %s [%s] %s\n", l.Time.Format(time.TimeOnly), l.Level, l.Message)
		}
	}
	return nil
}

func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: mihomac probe <http(s) URL>")
	}
	api, err := apiFor()
	if err != nil {
		return err
	}
	ctx, cancel := apiCtx()
	defer cancel()
	var r daemon.ProbeResult
	if err := api.Post(ctx, "/api/probe", map[string]string{"url": fs.Arg(0)}, &r); err != nil {
		return err
	}
	show := func(label string, a daemon.Attempt) {
		if a.OK {
			fmt.Printf("  %-26s HTTP %d in %d ms\n", label, a.Status, a.Millis)
		} else {
			fmt.Printf("  %-26s failed after %d ms: %s\n", label, a.Millis, firstNonEmpty(a.Error, "HTTP "+strconv.Itoa(a.Status)))
		}
	}
	fmt.Println(r.URL)
	show("direct (via "+r.DirectInterface+"):", r.Direct)
	show("through the proxy:", r.Proxied)
	fmt.Println("\n" + r.Verdict)
	return nil
}

func cmdInterfaces(args []string) error {
	fs := flag.NewFlagSet("interfaces", flag.ExitOnError)
	fs.Parse(args)
	api, err := apiFor()
	if err != nil {
		return err
	}
	ctx, cancel := apiCtx()
	defer cancel()
	var ifs []daemon.Iface
	if err := api.Get(ctx, "/api/interfaces", &ifs); err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tUP\tROUTES\tADDRESSES\tROLE")
	for _, i := range ifs {
		fmt.Fprintf(w, "%s\t%v\t%d\t%s\t%s\n", i.Name, i.Up, i.Routes, strings.Join(i.Addrs, " "), i.Role)
	}
	return w.Flush()
}

func cmdMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	setup := fs.Bool("setup", false, "print setup instructions for Claude, Cursor, and other MCP clients, then exit")
	fs.Parse(args)
	if *setup {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		fmt.Print(mcp.SetupInstructions(exe))
		return nil
	}
	home, err := resolve()
	if err != nil {
		return err
	}
	api, err := client.Connect(home, client.TokenAgent)
	if err != nil {
		return err
	}
	s := &mcp.Server{API: api, Version: buildinfo.Version}
	return s.Serve(context.Background(), os.Stdin, os.Stdout)
}

// cmdLogs prints the daemon's log or Clash Verge's.
func cmdLogs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	source := fs.String("source", "daemon", "daemon or verge")
	lines := fs.Int("n", 100, "number of lines")
	vdir := vergeDirFlag(fs)
	fs.Parse(args)
	home, err := resolve()
	if err != nil {
		return err
	}
	var path string
	switch *source {
	case "daemon":
		path = filepath.Join(home, daemon.DaemonLog)
	case "verge":
		vd, err := locateVerge(*vdir)
		if err != nil {
			return err
		}
		path = vd.LogFile()
	default:
		return fmt.Errorf("unknown log %q (want daemon or verge)", *source)
	}
	out, err := daemon.ReadLog(path, *lines)
	if err != nil {
		return err
	}
	if len(out) == 0 {
		fmt.Printf("No %s log yet (%s).\n", *source, path)
	}
	for _, l := range out {
		fmt.Println(l)
	}
	return nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func indentLines(s, prefix string) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString(prefix + l + "\n")
	}
	return b.String()
}

func orDash(s string) string { return firstNonEmpty(s, "-") }

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func byteSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
