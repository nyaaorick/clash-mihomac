package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"

	"github.com/nyaaorick/clash-mihomac/internal/daemon"
	"github.com/nyaaorick/clash-mihomac/internal/traffic"
)

const trafficUsage = `Usage:
  mihomac traffic [filters]              apps, surprises, and the busiest paths
  mihomac traffic interfaces             per-interface throughput and TUN-vs-NIC reconciliation
  mihomac traffic clear                  delete stored traffic history

Filters: --history [--range 15m]  --process APP  --proto tcp|udp|unix  --iface NAME
         --rule TEXT  --node NAME  --routing proxied|direct
The same view, as a diagram, is the Traffic tab in the GUI.
`

func cmdTraffic(args []string) error {
	fs := flag.NewFlagSet("traffic", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, trafficUsage) }
	name := instanceFlag(fs)
	history := fs.Bool("history", false, "show stored history instead of live flows")
	rng := fs.String("range", "15m", "history window (e.g. 15m, 6h)")
	q := url.Values{}
	for _, k := range []string{"process", "proto", "iface", "rule", "node", "routing"} {
		fs.Func(k, k+" filter", func(v string) error { q.Set(k, v); return nil })
	}
	var pos []string
	for rest := args; len(rest) > 0; {
		fs.Parse(rest)
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if *history {
		q.Set("mode", "history")
		q.Set("range", *rng)
	}
	api, _, err := apiFor(*name)
	if err != nil {
		return err
	}
	ctx, cancel := apiCtx()
	defer cancel()

	switch {
	case len(pos) == 1 && pos[0] == "clear":
		return api.Post(ctx, "/api/traffic/clear", map[string]string{}, nil)
	case len(pos) == 1 && pos[0] == "interfaces":
		var v daemon.TrafficInterfaces
		if err := api.Get(ctx, "/api/traffic/interfaces", &v); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "INTERFACE\tROLE\tIN/S\tOUT/S\tERR\tDROPS")
		for _, i := range v.Interfaces {
			in, out, errs, drops := "-", "-", "-", "-"
			if i.Rate != nil {
				in, out = byteSize(int64(i.Rate.InBps)), byteSize(int64(i.Rate.OutBps))
				errs, drops = fmt.Sprint(i.Rate.Errors), fmt.Sprint(i.Rate.Drops)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", i.Name, orDash(i.Role), in, out, errs, drops)
		}
		w.Flush()
		fmt.Println()
		for _, n := range v.Reconcile.Notes {
			fmt.Println(n)
		}
		return nil
	case len(pos) > 0:
		fmt.Fprint(os.Stderr, trafficUsage)
		return errors.New("unknown traffic command")
	}

	var v daemon.TrafficView
	if err := api.Get(ctx, "/api/traffic?"+q.Encode(), &v); err != nil {
		return err
	}
	for _, w := range v.Warnings {
		fmt.Println("warning:", w)
	}
	if len(v.Anomalies) > 0 {
		fmt.Println("Surprises:")
		for _, a := range v.Anomalies {
			fmt.Printf("  ! %s → %s: %s\n", a.Process, a.Remote, a.Detail)
		}
		fmt.Println()
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "APP\tFLOWS\tTCP\tUDP\tUNIX\tUP\tDOWN\tPROXIED")
	for _, p := range v.Processes {
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%s\t%s\t%.0f%%\n", p.Name, p.Flows, p.TCP, p.UDP, p.Unix, byteSize(p.Upload), byteSize(p.Download), p.ProxiedShare*100)
	}
	w.Flush()

	fmt.Println("\nBusiest paths:")
	var flows []traffic.Flow
	if err := api.Get(ctx, "/api/traffic/flows?limit=10&"+q.Encode(), &flows); err != nil {
		return err
	}
	for _, f := range flows {
		path := firstNonEmpty(f.Ingress, "no TUN") + " → " + firstNonEmpty(f.Node, "?") + " → " + firstNonEmpty(f.Egress, "?")
		fmt.Printf("  %-18s %-10s %s  %s  %s\n", traffic.AppName(f.Process), f.Proto, firstNonEmpty(f.Host, f.Remote), path, byteSize(f.Bytes()))
	}
	return nil
}
