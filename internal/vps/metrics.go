package vps

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// metricsScript only reads. It samples CPU and network counters twice, a
// second apart, so rates can be computed from one connection.
const metricsScript = `
echo "@@cpu1"; head -1 /proc/stat
echo "@@net1"; cat /proc/net/dev
sleep 1
echo "@@cpu2"; head -1 /proc/stat
echo "@@net2"; cat /proc/net/dev
echo "@@iface"; ip -o route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}'
echo "@@mem"; grep -E '^(MemTotal|MemAvailable):' /proc/meminfo
echo "@@disk"; df -Pk / | awk 'NR==2{print $2, $3}'
echo "@@load"; cat /proc/loadavg
echo "@@uptime"; cat /proc/uptime
echo "@@service"; systemctl is-active sing-box 2>/dev/null
echo "@@version"; /usr/local/bin/sing-box version 2>/dev/null | head -1
echo "@@ports"; ss -H -ltn 2>/dev/null | awk '{print $4}'
echo "@@certs"; for f in $(grep -o '"certificate_path": *"[^"]*"' /etc/sing-box/config.json 2>/dev/null | sed 's/.*: *"//; s/"$//'); do echo "$f $(openssl x509 -enddate -noout -in "$f" 2>/dev/null)"; done
echo "@@end"
`

// Metrics is one reading of a server's health.
type Metrics struct {
	Time        time.Time `json:"time"`
	CPUPercent  float64   `json:"cpu_percent"`
	MemTotalMB  int       `json:"mem_total_mb"`
	MemUsedPct  float64   `json:"mem_used_percent"`
	DiskTotalGB float64   `json:"disk_total_gb"`
	DiskUsedPct float64   `json:"disk_used_percent"`
	Load1       float64   `json:"load1"`
	Load5       float64   `json:"load5"`
	Load15      float64   `json:"load15"`
	UptimeSecs  int64     `json:"uptime_seconds"`
	Iface       string    `json:"iface,omitempty"`
	RxBps       float64   `json:"rx_bps"`
	TxBps       float64   `json:"tx_bps"`
	RxTotal     uint64    `json:"rx_total"` // counters since boot, for quota accounting
	TxTotal     uint64    `json:"tx_total"`

	ServiceActive  bool       `json:"service_active"`
	ServiceVersion string     `json:"service_version,omitempty"`
	Listening      []int      `json:"listening,omitempty"`
	CertExpiry     []CertInfo `json:"certs,omitempty"`
}

// CertInfo is a certificate's expiry.
type CertInfo struct {
	Path    string    `json:"path"`
	Expires time.Time `json:"expires"`
}

// Collect reads a server's metrics over conn.
func Collect(ctx context.Context, conn Conn, now time.Time) (Metrics, error) {
	r, err := conn.Run(ctx, "sh -c "+shq(metricsScript), nil)
	if err != nil {
		return Metrics{}, err
	}
	return ParseMetrics(r.Stdout, now)
}

// ParseMetrics reads metricsScript's output.
func ParseMetrics(out string, now time.Time) (Metrics, error) {
	sec := map[string][]string{}
	cur := ""
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if m, ok := strings.CutPrefix(line, "@@"); ok {
			cur = m
			continue
		}
		if cur != "" && strings.TrimSpace(line) != "" {
			sec[cur] = append(sec[cur], line)
		}
	}
	m := Metrics{Time: now}
	idle1, total1, ok1 := cpuTimes(sec["cpu1"])
	idle2, total2, ok2 := cpuTimes(sec["cpu2"])
	if !ok1 || !ok2 {
		return Metrics{}, fmt.Errorf("the server's CPU counters couldn't be read")
	}
	if dt := total2 - total1; dt > 0 {
		m.CPUPercent = 100 * (1 - float64(idle2-idle1)/float64(dt))
	}
	m.CPUPercent = clamp(m.CPUPercent, 0, 100)

	m.Iface = firstLine(sec["iface"])
	rx1, tx1, ok1 := netTotals(sec["net1"], m.Iface)
	rx2, tx2, ok2 := netTotals(sec["net2"], m.Iface)
	if ok1 && ok2 {
		m.RxTotal, m.TxTotal = rx2, tx2
		if rx2 >= rx1 {
			m.RxBps = float64(rx2 - rx1)
		}
		if tx2 >= tx1 {
			m.TxBps = float64(tx2 - tx1)
		}
	}
	var memTotal, memAvail float64
	for _, l := range sec["mem"] {
		f := strings.Fields(l)
		if len(f) >= 2 {
			v, _ := strconv.ParseFloat(f[1], 64)
			switch f[0] {
			case "MemTotal:":
				memTotal = v
			case "MemAvailable:":
				memAvail = v
			}
		}
	}
	if memTotal > 0 {
		m.MemTotalMB = int(memTotal / 1024)
		m.MemUsedPct = clamp(100*(memTotal-memAvail)/memTotal, 0, 100)
	}
	if f := strings.Fields(firstLine(sec["disk"])); len(f) == 2 {
		total, _ := strconv.ParseFloat(f[0], 64)
		used, _ := strconv.ParseFloat(f[1], 64)
		if total > 0 {
			m.DiskTotalGB = total / (1 << 20)
			m.DiskUsedPct = clamp(100*used/total, 0, 100)
		}
	}
	if f := strings.Fields(firstLine(sec["load"])); len(f) >= 3 {
		m.Load1, _ = strconv.ParseFloat(f[0], 64)
		m.Load5, _ = strconv.ParseFloat(f[1], 64)
		m.Load15, _ = strconv.ParseFloat(f[2], 64)
	}
	if f := strings.Fields(firstLine(sec["uptime"])); len(f) >= 1 {
		u, _ := strconv.ParseFloat(f[0], 64)
		m.UptimeSecs = int64(u)
	}
	m.ServiceActive = firstLine(sec["service"]) == "active"
	m.ServiceVersion = strings.TrimPrefix(firstLine(sec["version"]), "sing-box version ")
	seen := map[int]bool{}
	for _, l := range sec["ports"] {
		if i := strings.LastIndex(l, ":"); i >= 0 {
			if p, err := strconv.Atoi(l[i+1:]); err == nil && !seen[p] {
				seen[p] = true
				m.Listening = append(m.Listening, p)
			}
		}
	}
	for _, l := range sec["certs"] {
		path, rest, _ := strings.Cut(l, " ")
		if v, ok := strings.CutPrefix(strings.TrimSpace(rest), "notAfter="); ok {
			if t, err := time.Parse("Jan _2 15:04:05 2006 MST", v); err == nil {
				m.CertExpiry = append(m.CertExpiry, CertInfo{Path: path, Expires: t})
			}
		}
	}
	return m, nil
}

func firstLine(ls []string) string {
	if len(ls) == 0 {
		return ""
	}
	return strings.TrimSpace(ls[0])
}

func clamp(v, lo, hi float64) float64 { return max(lo, min(hi, v)) }

// cpuTimes parses the aggregate "cpu" line of /proc/stat into idle and total jiffies.
func cpuTimes(ls []string) (idle, total uint64, ok bool) {
	f := strings.Fields(firstLine(ls))
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, false
	}
	for i, s := range f[1:] {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		if i < 8 { // user nice system idle iowait irq softirq steal
			total += v
		}
		if i == 3 || i == 4 {
			idle += v
		}
	}
	return idle, total, true
}

// netTotals returns the receive and transmit byte counters for iface from
// /proc/net/dev, or the sum over every non-loopback interface if iface is empty.
func netTotals(ls []string, iface string) (rx, tx uint64, ok bool) {
	for _, l := range ls {
		name, rest, found := strings.Cut(l, ":")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "lo" || (iface != "" && name != iface) {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		r, err1 := strconv.ParseUint(f[0], 10, 64)
		t, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		rx, tx, ok = rx+r, tx+t, true
	}
	return
}

// State is a machine's overall condition.
type State string

// Machine states.
const (
	StateOnline      State = "online"
	StateDegraded    State = "degraded"
	StateUnreachable State = "unreachable"
	StateUnknown     State = "unknown"
)

// Judge derives a machine's state and the reasons for it.
func Judge(m Metrics, now time.Time) (State, []string) {
	var why []string
	if !m.ServiceActive {
		why = append(why, "the proxy service isn't running")
	}
	if m.DiskUsedPct >= 90 {
		why = append(why, fmt.Sprintf("disk is %.0f%% full", m.DiskUsedPct))
	}
	if m.MemUsedPct >= 95 {
		why = append(why, fmt.Sprintf("memory is %.0f%% used", m.MemUsedPct))
	}
	for _, c := range m.CertExpiry {
		switch days := c.Expires.Sub(now).Hours() / 24; {
		case days < 0:
			why = append(why, fmt.Sprintf("certificate %s expired", c.Path))
		case days < 14:
			why = append(why, fmt.Sprintf("certificate %s expires in %.0f days", c.Path, days))
		}
	}
	if len(why) > 0 {
		return StateDegraded, why
	}
	return StateOnline, nil
}
