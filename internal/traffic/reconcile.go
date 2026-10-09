package traffic

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Delta subtracts two counter snapshots, per interface. A counter that went
// backwards (an interface that was reset or recreated) counts from zero.
func Delta(before, after map[string]IfaceCounters) map[string]IfaceCounters {
	sub := func(a, b uint64) uint64 {
		if a < b {
			return a
		}
		return a - b
	}
	out := map[string]IfaceCounters{}
	for name, a := range after {
		b := before[name]
		out[name] = IfaceCounters{
			Name:    name,
			InBytes: sub(a.InBytes, b.InBytes), OutBytes: sub(a.OutBytes, b.OutBytes),
			InPkts: sub(a.InPkts, b.InPkts), OutPkts: sub(a.OutPkts, b.OutPkts),
			InErrs: sub(a.InErrs, b.InErrs), OutErrs: sub(a.OutErrs, b.OutErrs),
			Drops: sub(a.Drops, b.Drops),
		}
	}
	return out
}

// IfaceRate is an interface's throughput over a window.
type IfaceRate struct {
	Name       string  `json:"name"`
	InBps      float64 `json:"in_bps"` // bytes per second
	OutBps     float64 `json:"out_bps"`
	InPktsPS   float64 `json:"in_pps"`
	OutPktsPS  float64 `json:"out_pps"`
	Errors     uint64  `json:"errors"`
	Drops      uint64  `json:"drops"`
	TotalIn    uint64  `json:"total_in"`
	TotalOut   uint64  `json:"total_out"`
	WindowSecs float64 `json:"window_seconds"`
}

// Rates turns a counter delta over window into per-second rates.
func Rates(delta, totals map[string]IfaceCounters, window time.Duration) []IfaceRate {
	secs := window.Seconds()
	if secs <= 0 {
		secs = 1
	}
	var out []IfaceRate
	for name, d := range delta {
		out = append(out, IfaceRate{
			Name: name, InBps: float64(d.InBytes) / secs, OutBps: float64(d.OutBytes) / secs,
			InPktsPS: float64(d.InPkts) / secs, OutPktsPS: float64(d.OutPkts) / secs,
			Errors: d.InErrs + d.OutErrs, Drops: d.Drops,
			TotalIn: totals[name].InBytes, TotalOut: totals[name].OutBytes, WindowSecs: secs,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Reconciliation compares what went into our TUN with what left the
// physical NICs, and explains the difference.
//
// From the kernel's side, a utun's "out" counter is data sent to its reader
// (mihomo): the apps' upstream traffic. Its "in" counter is data its reader
// wrote back: downstream to the apps.
type Reconciliation struct {
	Window  time.Duration `json:"window_ns"`
	TUN     string        `json:"tun"`
	TunUp   uint64        `json:"tun_up"`   // apps → TUN
	TunDown uint64        `json:"tun_down"` // TUN → apps
	NICUp   uint64        `json:"nic_up"`   // physical NICs, leaving the machine
	NICDown uint64        `json:"nic_down"`
	GapUp   int64         `json:"gap_up"` // NICUp - TunUp
	GapDown int64         `json:"gap_down"`
	NICs    []string      `json:"nics"`
	Notes   []string      `json:"notes"`
}

func physicalNIC(name string) bool {
	return strings.HasPrefix(name, "en") || strings.HasPrefix(name, "bridge")
}

// Reconcile explains the gap between TUN and NIC byte counts over a window.
// flows are the flows seen during it.
func Reconcile(delta map[string]IfaceCounters, ownTUN string, flows []Flow, window time.Duration) Reconciliation {
	r := Reconciliation{Window: window, TUN: ownTUN}
	if t, ok := delta[ownTUN]; ok {
		r.TunUp, r.TunDown = t.OutBytes, t.InBytes
	}
	for name, d := range delta {
		if physicalNIC(name) {
			r.NICs = append(r.NICs, name)
			r.NICUp += d.OutBytes
			r.NICDown += d.InBytes
		}
	}
	sort.Strings(r.NICs)
	r.GapUp = int64(r.NICUp) - int64(r.TunUp)
	r.GapDown = int64(r.NICDown) - int64(r.TunDown)

	var proxied, direct, rejected int64
	var bypassFlows, otherVPN int
	for _, f := range flows {
		switch {
		case f.Node == "REJECT" || f.Node == "REJECT-DROP":
			rejected += f.Upload
		case f.Proxied:
			proxied += f.Upload
		default:
			direct += f.Upload
		}
		for _, a := range f.Anomalies {
			switch a.Kind {
			case AnomalyBypassedTUN, AnomalyWrongNIC:
				bypassFlows++
			case AnomalyOtherVPN:
				otherVPN++
			}
		}
	}

	if ownTUN == "" {
		r.Notes = append(r.Notes, "This instance isn't in TUN mode, so there is no tunnel to compare against.")
		return r
	}
	if len(r.NICs) == 0 {
		r.Notes = append(r.Notes, "No physical NIC counters were available.")
		return r
	}
	r.Notes = append(r.Notes, fmt.Sprintf("Apps sent %s into %s; mihomo's own accounting says %s of it was proxied, %s direct, and %s was rejected before leaving.",
		humanBytes(int64(r.TunUp)), ownTUN, humanBytes(proxied), humanBytes(direct), humanBytes(rejected)))
	switch {
	case r.TunUp == 0 && r.NICUp == 0:
		r.Notes = append(r.Notes, "No traffic in this window.")
	case r.GapUp > 0:
		why := []string{"the proxy protocol's own framing, handshakes, and retransmits", "DNS and system traffic that doesn't pass through the TUN"}
		if bypassFlows > 0 {
			why = append(why, fmt.Sprintf("%d flows that bypass TUN entirely (see the warnings)", bypassFlows))
		}
		if otherVPN > 0 {
			why = append(why, fmt.Sprintf("%d flows routed through another VPN's tunnel", otherVPN))
		}
		r.Notes = append(r.Notes, fmt.Sprintf("The physical NICs sent %s more than the TUN received (%.0f%% extra). That gap is made up of %s.",
			humanBytes(r.GapUp), 100*float64(r.GapUp)/float64(max(r.TunUp, 1)), strings.Join(why, "; ")))
	case r.GapUp < 0:
		r.Notes = append(r.Notes, fmt.Sprintf("The physical NICs sent %s less than the TUN received: %s of it was rejected or is still buffered in connections that haven't flushed.",
			humanBytes(-r.GapUp), humanBytes(rejected)))
	default:
		r.Notes = append(r.Notes, "Upstream bytes match exactly.")
	}
	if r.GapDown > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("The physical NICs received %s more than the TUN delivered back: encapsulation overhead plus traffic that never entered TUN.", humanBytes(r.GapDown)))
	} else if r.GapDown < 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("The TUN delivered %s more than the physical NICs received: mihomo answered some requests itself (for example DNS from its cache).", humanBytes(-r.GapDown)))
	}
	return r
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
