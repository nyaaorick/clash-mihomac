package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/daemon"
	"github.com/nyaaorick/clash-mihomac/internal/rules"
)

const healthUsage = `Usage:
  mihomac health                 every node's health: state, uptime, latency, and why it is failing
  mihomac health <node>          one node's recent checks
  mihomac health check [node]    run the checks now instead of waiting for the schedule

Nodes are checked every couple of minutes through mihomo's delay test. A node that fails is
examined stage by stage (DNS, TCP, TLS) to tell blocking (DNS poisoning, TCP reset, TLS
handshake failure) from an ordinary outage. Only a failing node triggers those extra probes.
`

func cmdHealth(args []string) error {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, healthUsage) }
	name := instanceFlag(fs)
	var pos []string
	for rest := args; len(rest) > 0; {
		fs.Parse(rest)
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	api, _, err := apiFor(*name)
	if err != nil {
		return err
	}
	ctx, cancel := apiCtx()
	defer cancel()

	var view daemon.HealthView
	switch {
	case len(pos) > 0 && pos[0] == "check":
		body := map[string]string{}
		if len(pos) > 1 {
			body["node"] = pos[1]
		}
		fmt.Println("Checking…")
		if err := api.Post(ctx, "/api/health/check", body, &view); err != nil {
			return err
		}
	case len(pos) == 1:
		var nh daemon.NodeHealth
		if err := api.Get(ctx, "/api/health/"+url.PathEscape(pos[0]), &nh); err != nil {
			return err
		}
		s := nh.Summary
		fmt.Printf("%s: %s", s.Node, s.State)
		if s.Reason != "" {
			fmt.Printf(" — %s", s.Reason)
		}
		fmt.Printf("\nUptime (24h) %s, average latency %s, %d checks stored\n\n", pct(s.Uptime24h), ms(s.AvgDelayMs), s.Checks)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for i, c := range nh.Checks {
			if i == 40 {
				break
			}
			result := "ok " + ms(c.DelayMs)
			if !c.OK {
				result = fmt.Sprintf("FAILED %s (%s): %s", c.Kind, c.Stage, c.Detail)
			}
			fmt.Fprintf(w, "%s\t%s\n", c.Time.Local().Format("01-02 15:04:05"), result)
		}
		return w.Flush()
	case len(pos) == 0:
		if err := api.Get(ctx, "/api/health", &view); err != nil {
			return err
		}
	default:
		fmt.Fprint(os.Stderr, healthUsage)
		return errors.New("too many arguments")
	}

	if len(view.Nodes) == 0 {
		fmt.Println("No health checks yet; the first round runs shortly after the instance starts (or run `mihomac health check`).")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NODE\tSTATE\tUPTIME 24H\tAVG\tSINCE\tNOTE")
	for _, s := range view.Nodes {
		since := ""
		if !s.Since.IsZero() {
			since = time.Since(s.Since).Round(time.Second).String() + " ago"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", s.Node, s.State, pct(s.Uptime24h), ms(s.AvgDelayMs), since, s.Reason)
	}
	w.Flush()
	for _, n := range view.Overview {
		fmt.Println("\n" + n)
	}
	return nil
}

func pct(f float64) string {
	if f < 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", f*100)
}

func ms(n int) string {
	if n <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d ms", n)
}

const groupsUsage = `Usage:
  mihomac groups [list]
  mihomac groups set NAME --type fallback|url-test|load-balance --members a,b,c [options] [--yes]
  mihomac groups remove NAME [--yes]

A group switches between nodes from your config automatically, and rules can use it as a target
(mihomac rules add --target NAME). Types:
  fallback       the first healthy member, in the order given
  url-test       the fastest member; --tolerance MS stops it flapping between near-equal nodes
  load-balance   spread connections over healthy members; --strategy consistent-hashing|round-robin|sticky-sessions
Options: --url (health-check URL), --interval SECONDS, --timeout MS, --max-failed N

Like all config changes, set and remove show a preview and stop; add --yes to apply.
`

func cmdGroups(args []string) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("groups "+sub, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, groupsUsage) }
	name := instanceFlag(fs)
	typ := fs.String("type", "", "fallback, url-test, or load-balance")
	members := fs.String("members", "", "comma-separated nodes or groups from your config")
	checkURL := fs.String("url", "", "health-check URL")
	interval := fs.Int("interval", 0, "seconds between health checks")
	timeout := fs.Int("timeout", 0, "health-check timeout in ms")
	tolerance := fs.Int("tolerance", 0, "url-test: ms a member must be faster by before switching")
	strategy := fs.String("strategy", "", "load-balance strategy")
	maxFailed := fs.Int("max-failed", 0, "failed checks in a row before a member is unhealthy")
	yes := fs.Bool("yes", false, "apply the change instead of only previewing it")
	var pos []string
	for rest := args; len(rest) > 0; {
		fs.Parse(rest)
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	_, inst, err := resolve(*name)
	if err != nil {
		return err
	}
	set, err := currentRuleSet(inst)
	if err != nil {
		return err
	}

	var change rules.Change
	switch sub {
	case "list":
		if len(set.Groups) == 0 {
			fmt.Println("No failover groups. Create one with `mihomac groups set`.")
		}
		for _, g := range set.Groups {
			fmt.Println(g.Describe())
		}
		return nil
	case "set":
		if len(pos) != 1 {
			return errors.New("usage: mihomac groups set NAME --type T --members a,b")
		}
		var ms []string
		for _, m := range strings.Split(*members, ",") {
			if m = strings.TrimSpace(m); m != "" {
				ms = append(ms, m)
			}
		}
		g := rules.Group{Name: pos[0], Type: *typ, Members: ms, URL: *checkURL, Interval: *interval, Timeout: *timeout,
			Tolerance: *tolerance, Strategy: *strategy, MaxFailed: *maxFailed}
		if err := g.Validate(); err != nil {
			return err
		}
		change.SetGroups = []rules.Group{g}
	case "remove":
		if len(pos) != 1 {
			return errors.New("usage: mihomac groups remove NAME")
		}
		change.RemoveGroups = []string{pos[0]}
	default:
		fmt.Fprint(os.Stderr, groupsUsage)
		return fmt.Errorf("unknown groups command %q", sub)
	}
	diff, err := set.Diff(change)
	if err != nil {
		return err
	}
	if !*yes || running(inst) {
		fmt.Print(diff)
	}
	if !*yes {
		fmt.Println("\nThis is a preview; nothing has changed. Re-run with --yes to apply.")
		return nil
	}
	return changeRules(inst, change)
}
