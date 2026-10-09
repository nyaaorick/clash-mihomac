package vps

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"
)

// shq quotes s for a POSIX shell.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// preflightScript only reads. Each section starts with a marker line.
const preflightScript = `
echo "@@uid"; id -u
echo "@@os"; cat /etc/os-release 2>/dev/null
echo "@@arch"; uname -m
echo "@@systemd"; if [ -d /run/systemd/system ]; then echo yes; else echo no; fi
echo "@@listen"; ss -H -ltnup 2>/dev/null || netstat -ltnup 2>/dev/null
echo "@@services"; systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null | awk '{print $1}'
echo "@@dirs"; ls -d /etc/v2ray-agent /etc/sing-box /usr/local/etc/xray /etc/xray /etc/hysteria /usr/local/bin/sing-box 2>/dev/null
echo "@@ntp"; timedatectl show -p NTPSynchronized --value 2>/dev/null
echo "@@mem"; awk '/MemTotal/{print int($2/1024)}' /proc/meminfo
echo "@@disk"; df -Pm / 2>/dev/null | awk 'NR==2{print $4}'
echo "@@cc"; sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null; sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null
echo "@@firewall"; if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then echo ufw; elif systemctl is-active firewalld >/dev/null 2>&1; then echo firewalld; else echo none; fi
echo "@@pkg"; for p in apt-get dnf yum; do if command -v $p >/dev/null 2>&1; then echo $p; break; fi; done
echo "@@ours"; [ -x /usr/local/bin/sing-box ] && echo binary; [ -f /etc/sing-box/config.json ] && echo config; [ -f /etc/systemd/system/sing-box.service ] && echo unit; systemctl is-active sing-box 2>/dev/null; /usr/local/bin/sing-box version 2>/dev/null | head -1
echo "@@end"
`

// Issue severities.
const (
	SevError = "error" // setup can't proceed
	SevWarn  = "warning"
	SevInfo  = "info"
)

// Issue is something the pre-flight check found.
type Issue struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Report is what pre-flight learned about a server.
type Report struct {
	Reachable  bool           `json:"reachable"`
	HostKey    string         `json:"host_key,omitempty"`
	Root       bool           `json:"root"`
	OS         string         `json:"os,omitempty"` // PRETTY_NAME
	OSID       string         `json:"os_id,omitempty"`
	Arch       string         `json:"arch,omitempty"` // amd64 or arm64
	Systemd    bool           `json:"systemd"`
	PortsInUse map[int]string `json:"ports_in_use,omitempty"` // port → process
	Existing   []string       `json:"existing,omitempty"`     // proxy services and directories found
	OursFound  bool           `json:"ours_found"`             // a previous Clash Mihomac install
	Ours       Install        `json:"ours"`
	NTPSynced  *bool          `json:"ntp_synced,omitempty"`
	MemMB      int            `json:"mem_mb,omitempty"`
	DiskFreeMB int            `json:"disk_free_mb,omitempty"`
	BBRActive  bool           `json:"bbr_active"`
	BBRAvail   bool           `json:"bbr_available"`
	Firewall   string         `json:"firewall,omitempty"` // ufw, firewalld, or none
	PkgMgr     string         `json:"pkg_mgr,omitempty"`
	Issues     []Issue        `json:"issues"`
}

// Install is what exists of a previous sing-box install.
type Install struct {
	Binary  bool   `json:"binary"`
	Config  bool   `json:"config"`
	Unit    bool   `json:"unit"`
	Active  bool   `json:"active"`
	Version string `json:"version,omitempty"`
}

// Any reports whether any part of an install exists.
func (i Install) Any() bool { return i.Binary || i.Config || i.Unit }

// Blocked reports whether any issue stops setup.
func (r Report) Blocked() bool {
	for _, i := range r.Issues {
		if i.Severity == SevError {
			return true
		}
	}
	return false
}

// Preflight inspects the server. wantPort is the port the proxy will listen on.
func Preflight(ctx context.Context, c Conn, wantPort int) (Report, error) {
	res, err := c.Run(ctx, "sh -c "+shq(preflightScript), nil)
	if err != nil {
		return Report{}, err
	}
	r := ParsePreflight(res.Stdout)
	r.Reachable, r.HostKey = true, c.HostKey()
	r.Issues = Assess(r, wantPort)
	return r, nil
}

// ParsePreflight reads preflightScript's output.
func ParsePreflight(out string) Report {
	sections := map[string][]string{}
	cur := ""
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if m, ok := strings.CutPrefix(line, "@@"); ok {
			cur = m
			continue
		}
		if cur != "" && strings.TrimSpace(line) != "" {
			sections[cur] = append(sections[cur], line)
		}
	}
	first := func(k string) string {
		if v := sections[k]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	r := Report{PortsInUse: map[int]string{}}
	r.Root = first("uid") == "0"
	r.Systemd = first("systemd") == "yes"
	for _, l := range sections["os"] {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "PRETTY_NAME":
			r.OS = v
		case "ID":
			r.OSID = strings.ToLower(v)
		}
	}
	switch first("arch") {
	case "x86_64", "amd64":
		r.Arch = "amd64"
	case "aarch64", "arm64":
		r.Arch = "arm64"
	default:
		r.Arch = first("arch") // reported as-is; Assess flags it
	}
	for _, l := range sections["listen"] {
		if port, proc, ok := parseListenLine(l); ok {
			r.PortsInUse[port] = proc
		}
	}
	proxyNames := []string{"sing-box", "xray", "v2ray", "hysteria", "trojan", "shadowsocks", "ss-server", "tuic", "clash", "mihomo", "x-ui", "marzban"}
	for _, svc := range sections["services"] {
		for _, n := range proxyNames {
			if strings.Contains(strings.ToLower(svc), n) {
				r.Existing = append(r.Existing, svc)
				break
			}
		}
	}
	for _, d := range sections["dirs"] {
		d = strings.TrimSpace(d)
		r.Existing = append(r.Existing, d)
		if d == "/usr/local/bin/sing-box" || d == "/etc/sing-box" {
			r.OursFound = true
		}
	}
	switch first("ntp") {
	case "yes":
		t := true
		r.NTPSynced = &t
	case "no":
		f := false
		r.NTPSynced = &f
	}
	r.MemMB, _ = strconv.Atoi(first("mem"))
	r.DiskFreeMB, _ = strconv.Atoi(first("disk"))
	if cc := sections["cc"]; len(cc) > 0 {
		r.BBRAvail = strings.Contains(cc[0], "bbr")
		if len(cc) > 1 {
			r.BBRActive = strings.TrimSpace(cc[len(cc)-1]) == "bbr"
		}
	}
	for _, l := range sections["ours"] {
		switch l = strings.TrimSpace(l); {
		case l == "binary":
			r.Ours.Binary = true
		case l == "config":
			r.Ours.Config = true
		case l == "unit":
			r.Ours.Unit = true
		case l == "active":
			r.Ours.Active = true
		case strings.HasPrefix(l, "sing-box version "):
			r.Ours.Version = strings.TrimPrefix(l, "sing-box version ")
		}
	}
	if r.Ours.Any() {
		r.OursFound = true
	}
	r.Firewall = first("firewall")
	r.PkgMgr = first("pkg")
	return r
}

// parseListenLine reads one `ss -ltnup` line:
//
//	tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=812,fd=6))
func parseListenLine(l string) (port int, proc string, ok bool) {
	f := strings.Fields(l)
	if len(f) < 5 {
		return 0, "", false
	}
	local := f[4]
	if f[0] != "tcp" && f[0] != "udp" {
		return 0, "", false
	}
	i := strings.LastIndex(local, ":")
	if i < 0 {
		return 0, "", false
	}
	p, err := strconv.Atoi(local[i+1:])
	if err != nil {
		return 0, "", false
	}
	proc = "unknown process"
	if j := strings.Index(l, `(("`); j >= 0 {
		rest := l[j+3:]
		if k := strings.Index(rest, `"`); k >= 0 {
			proc = rest[:k]
		}
	}
	return p, proc, true
}

// supportedOS lists distributions the installer is written for.
var supportedOS = map[string]bool{"debian": true, "ubuntu": true, "centos": true, "rocky": true, "almalinux": true, "fedora": true, "rhel": true}

// Assess turns a report into the issues a person should see.
func Assess(r Report, wantPort int) []Issue {
	var out []Issue
	add := func(sev, format string, args ...any) { out = append(out, Issue{sev, fmt.Sprintf(format, args...)}) }
	if !r.Root {
		add(SevError, "You are not logged in as root. Setup installs system services, so it needs root (log in as root, or use a user that is root).")
	}
	if !r.Systemd {
		add(SevError, "This server doesn't use systemd, which the installer relies on to run the proxy as a service.")
	}
	if r.Arch != "amd64" && r.Arch != "arm64" {
		add(SevError, "Unsupported CPU architecture %q (supported: x86_64 and aarch64).", r.Arch)
	}
	if r.PkgMgr == "" {
		add(SevError, "No supported package manager (apt, dnf, yum) was found.")
	}
	if !supportedOS[r.OSID] {
		add(SevWarn, "%s isn't one of the systems the installer was written for (Debian, Ubuntu, CentOS/Rocky/Alma, Fedora); it may still work.", firstOr(r.OS, "This system"))
	}
	if proc, busy := r.PortsInUse[wantPort]; busy && !(r.OursFound && proc == "sing-box") {
		add(SevError, "Port %d is already in use by %s. Pick another port, or stop that service first.", wantPort, proc)
	}
	if len(r.Existing) > 0 {
		add(SevWarn, "Existing proxy software was found (%s). Setup won't touch anything it didn't create; if it is yours, expect a port or firewall clash.", strings.Join(r.Existing, ", "))
	}
	if r.NTPSynced != nil && !*r.NTPSynced {
		add(SevWarn, "The server clock isn't synchronized (NTP). Some protocols reject connections when the clock is off by more than a minute or two.")
	}
	if r.MemMB > 0 && r.MemMB < 256 {
		add(SevWarn, "Only %d MB of memory; the proxy will run but with little headroom.", r.MemMB)
	}
	if r.DiskFreeMB > 0 && r.DiskFreeMB < 300 {
		add(SevError, "Only %d MB of free disk space; the install needs about 300 MB.", r.DiskFreeMB)
	}
	if !r.BBRAvail {
		add(SevInfo, "BBR congestion control isn't available in this kernel, so it won't be enabled.")
	} else if r.BBRActive {
		add(SevInfo, "BBR is already active.")
	}
	if r.Firewall == "none" {
		add(SevInfo, "No managed firewall (ufw or firewalld) is active. If your provider has a network firewall, open port %d there too.", wantPort)
	}
	return out
}

func firstOr(s, def string) string {
	if s != "" {
		return s
	}
	return def
}
