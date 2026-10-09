package traffic

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
)

// ParseLsof reads `lsof -nP -w +c 0 -i -U -F pcLftPnT` output.
//
// In field output each line is a one-letter tag followed by a value. A
// 'p' line starts a process; an 'f' line starts one of its files. Only
// Internet and Unix sockets are kept.
func ParseLsof(out string) ([]Socket, error) {
	var socks []Socket
	var pid int
	var cmd, user string
	var cur *Socket
	flush := func() {
		if cur != nil && cur.Proto != "" {
			socks = append(socks, *cur)
		}
		cur = nil
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		tag, val := line[0], line[1:]
		switch tag {
		case 'p':
			flush()
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("lsof: bad pid %q", val)
			}
			pid, cmd, user = n, "", ""
		case 'c':
			cmd = val
		case 'L':
			user = val
		case 'f':
			flush()
			cur = &Socket{PID: pid, Command: cmd, User: user}
		case 't':
			if cur == nil {
				continue
			}
			switch val {
			case "IPv4":
				cur.Family = "ipv4"
			case "IPv6":
				cur.Family = "ipv6"
			case "unix":
				cur.Family, cur.Proto = "unix", ProtoUnix
			default:
				cur = nil // a regular file, pipe, or device
			}
		case 'P':
			if cur == nil || cur.Family == "unix" {
				continue
			}
			switch strings.ToUpper(val) {
			case "TCP":
				cur.Proto = ProtoTCP
			case "UDP":
				cur.Proto = ProtoUDP
			case "ICMP", "ICMPV6":
				cur.Proto = ProtoICMP
			default:
				cur.Proto = ProtoOther
			}
		case 'n':
			if cur == nil {
				continue
			}
			local, remote, _ := strings.Cut(val, "->")
			cur.Local, cur.Remote = local, remote
		case 'T':
			if cur == nil {
				continue
			}
			if st, ok := strings.CutPrefix(val, "ST="); ok {
				cur.State = st
				cur.Listening = st == "LISTEN"
			}
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// Unix sockets with no usable name are anonymous pairs; they carry no
	// information worth showing.
	out2 := socks[:0]
	for _, s := range socks {
		anon := func(a string) bool { return a == "" || strings.HasPrefix(a, "0x") }
		if s.Family == "unix" && anon(s.Local) && anon(s.Remote) {
			continue
		}
		out2 = append(out2, s)
	}
	return out2, nil
}

// ParseIfaceCounters reads `netstat -ibd` output, taking the link-level
// row of each interface (the per-address rows repeat the same counters).
func ParseIfaceCounters(out string) (map[string]IfaceCounters, error) {
	res := map[string]IfaceCounters{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// Name Mtu Network [Address] Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll Drop
		if len(f) < 11 || !strings.HasPrefix(f[2], "<Link#") {
			continue
		}
		n := f[len(f)-8:]
		var v [8]uint64
		ok := true
		for i := range v {
			var err error
			if n[i] == "-" {
				continue
			}
			if v[i], err = strconv.ParseUint(n[i], 10, 64); err != nil {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		name := strings.TrimSuffix(f[0], "*") // a trailing * marks an interface that is down
		res[name] = IfaceCounters{Name: name, InPkts: v[0], InErrs: v[1], InBytes: v[2], OutPkts: v[3], OutErrs: v[4], OutBytes: v[5], Drops: v[7]}
	}
	if len(res) == 0 {
		return nil, errors.New("netstat -ib: no interface rows found")
	}
	return res, nil
}

// ParseRoutes reads `netstat -rn` output.
func ParseRoutes(out string) ([]Route, error) {
	var routes []Route
	v6 := false
	seenSection := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "Internet:":
			v6, seenSection = false, true
			continue
		case trimmed == "Internet6:":
			v6, seenSection = true, true
			continue
		case trimmed == "" || strings.HasPrefix(trimmed, "Destination") || strings.HasPrefix(trimmed, "Routing tables"):
			continue
		}
		f := strings.Fields(trimmed)
		if len(f) < 4 || !seenSection {
			continue
		}
		dest, err := parseRouteDest(f[0], v6)
		if err != nil {
			continue
		}
		gw := ""
		if g := strings.SplitN(f[1], "%", 2)[0]; !strings.HasPrefix(f[1], "link#") {
			if a, err := netip.ParseAddr(g); err == nil {
				gw = a.String()
			}
		}
		routes = append(routes, Route{Dest: dest.String(), Gateway: gw, Flags: f[2], Iface: f[3]})
	}
	if len(routes) == 0 {
		return nil, errors.New("netstat -rn: no routes found")
	}
	return routes, nil
}

// parseRouteDest understands netstat's shorthand: "default", "10.1" (a
// class-style prefix with one byte per dotted part), "192.168.1/24",
// "fe80::%lo0/64".
func parseRouteDest(s string, v6 bool) (netip.Prefix, error) {
	if s == "default" {
		if v6 {
			return netip.MustParsePrefix("::/0"), nil
		}
		return netip.MustParsePrefix("0.0.0.0/0"), nil
	}
	addr, bits, hasBits := strings.Cut(s, "/")
	if i := strings.Index(addr, "%"); i >= 0 {
		addr = addr[:i]
	}
	if v6 {
		a, err := netip.ParseAddr(addr)
		if err != nil {
			return netip.Prefix{}, err
		}
		n := 128
		if hasBits {
			if n, err = strconv.Atoi(bits); err != nil {
				return netip.Prefix{}, err
			}
		}
		return a.Prefix(n)
	}
	parts := strings.Split(addr, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return netip.Prefix{}, fmt.Errorf("bad destination %q", s)
	}
	n := len(parts) * 8
	for len(parts) < 4 {
		parts = append(parts, "0")
	}
	a, err := netip.ParseAddr(strings.Join(parts, "."))
	if err != nil {
		return netip.Prefix{}, err
	}
	if hasBits {
		if n, err = strconv.Atoi(bits); err != nil {
			return netip.Prefix{}, err
		}
	}
	return a.Prefix(n)
}

// ParsePS reads `ps -axo pid=,ppid=,comm=` into pid → (ppid, command path).
func ParsePS(out string) map[int]PSEntry {
	res := map[int]PSEntry{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		ppid, err2 := strconv.Atoi(f[1])
		if err1 != nil || err2 != nil {
			continue
		}
		path := strings.Join(f[2:], " ") // comm can contain spaces
		res[pid] = PSEntry{PPID: ppid, Path: path}
	}
	return res
}

// PSEntry is one process-table row.
type PSEntry struct {
	PPID int
	Path string
}

// ParseCodesign extracts the signing identity from `codesign -dvv` output
// (which goes to stderr).
func ParseCodesign(out string) string {
	var authority, team, id string
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "Authority=") && authority == "":
			authority = strings.TrimPrefix(line, "Authority=")
		case strings.HasPrefix(line, "TeamIdentifier="):
			team = strings.TrimPrefix(line, "TeamIdentifier=")
		case strings.HasPrefix(line, "Identifier=") && id == "":
			id = strings.TrimPrefix(line, "Identifier=")
		case strings.Contains(line, "code object is not signed"):
			return "unsigned"
		}
	}
	switch {
	case authority != "" && team != "" && team != "not set":
		return fmt.Sprintf("%s (team %s)", authority, team)
	case authority != "":
		return authority
	case id != "":
		return id + " (ad hoc)"
	}
	return ""
}

// BundleOf returns the path of the outermost .app bundle containing path.
func BundleOf(path string) string {
	parts := strings.Split(path, string(filepath.Separator))
	for i, p := range parts {
		if strings.HasSuffix(p, ".app") && i > 0 {
			return strings.Join(parts[:i+1], string(filepath.Separator))
		}
	}
	return ""
}
