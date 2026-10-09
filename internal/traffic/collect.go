package traffic

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Runner runs a system command and returns its combined output. It matches
// netstate.Runner, so the same fakes work.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// SocketSource supplies the socket table. The privileged helper is the
// best source (it sees every process); lsof run as the user is the fallback.
type SocketSource interface {
	Sockets(ctx context.Context) ([]Socket, error)
}

// LsofSockets reads the socket table with lsof as the current user, which
// only shows that user's own processes.
type LsofSockets struct{ Run Runner }

// Sockets implements SocketSource.
func (l LsofSockets) Sockets(ctx context.Context) ([]Socket, error) {
	out, err := l.Run.Run(ctx, "/usr/sbin/lsof", "-nP", "-w", "+c", "0", "-i", "-U", "-F", "pcLftPnT")
	if err != nil && out == "" {
		return nil, err
	}
	return ParseLsof(out)
}

// Collector gathers the system-side inputs, caching what is expensive.
type Collector struct {
	Run     Runner
	Sockets SocketSource // defaults to LsofSockets

	mu       sync.Mutex
	ps       map[int]PSEntry
	psAt     time.Time
	counters map[string]IfaceCounters
	signed   map[string]string // executable path → signing identity
	bundleID map[string]string // bundle path → bundle identifier
	now      func() time.Time
}

// SystemState is one reading of the machine's network state.
type SystemState struct {
	Time      time.Time
	Sockets   []Socket
	Routes    *RouteTable
	Counters  map[string]IfaceCounters
	PS        map[int]PSEntry
	AddrOwner map[netip.Addr]string
	// Warnings lists sources that failed; the rest of the state is still valid.
	Warnings []string
}

// Read takes a reading. Sources that fail are skipped with a warning, so a
// missing lsof never hides the route table.
func (c *Collector) Read(ctx context.Context) SystemState {
	st := SystemState{Time: c.clock()}
	warn := func(what string, err error) { st.Warnings = append(st.Warnings, what+": "+err.Error()) }

	src := c.Sockets
	if src == nil {
		src = LsofSockets{Run: c.Run}
	}
	var err error
	if st.Sockets, err = src.Sockets(ctx); err != nil {
		warn("socket table", err)
	}
	if out, err := c.Run.Run(ctx, "/usr/sbin/netstat", "-rn"); err != nil && out == "" {
		warn("route table", err)
	} else if routes, err := ParseRoutes(out); err != nil {
		warn("route table", err)
	} else {
		st.Routes = NewRouteTable(routes)
	}
	if out, err := c.Run.Run(ctx, "/usr/sbin/netstat", "-ibd"); err != nil && out == "" {
		warn("interface counters", err)
	} else if counters, err := ParseIfaceCounters(out); err != nil {
		warn("interface counters", err)
	} else {
		st.Counters = counters
	}
	st.PS = c.processTable(ctx)
	st.AddrOwner = AddrOwners()
	return st
}

func (c *Collector) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *Collector) processTable(ctx context.Context) map[int]PSEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ps != nil && c.clock().Sub(c.psAt) < 5*time.Second {
		return c.ps
	}
	if out, err := c.Run.Run(ctx, "/bin/ps", "-axo", "pid=,ppid=,comm="); err == nil || out != "" {
		c.ps, c.psAt = ParsePS(out), c.clock()
	}
	return c.ps
}

// maxEnrichPerRead bounds codesign/plutil runs per call; the rest are
// filled in on later reads as the cache warms.
const maxEnrichPerRead = 8

// Enrich adds the code-signing identity and bundle identifier to flows'
// processes. Results are cached per executable and per bundle.
func (c *Collector) Enrich(ctx context.Context, flows []Flow) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.signed == nil {
		c.signed, c.bundleID = map[string]string{}, map[string]string{}
	}
	budget := maxEnrichPerRead
	for i := range flows {
		p := &flows[i].Process
		if p.Path != "" && filepath.IsAbs(p.Path) {
			sig, ok := c.signed[p.Path]
			if !ok && budget > 0 {
				budget--
				out, _ := c.Run.Run(ctx, "/usr/bin/codesign", "-dvv", p.Path)
				sig = ParseCodesign(out)
				c.signed[p.Path], ok = sig, true
			}
			p.Signature = sig
		}
		if p.Bundle != "" {
			id, ok := c.bundleID[p.Bundle]
			if !ok && budget > 0 {
				budget--
				out, err := c.Run.Run(ctx, "/usr/bin/plutil", "-extract", "CFBundleIdentifier", "raw", "-o", "-", filepath.Join(p.Bundle, "Contents", "Info.plist"))
				if err == nil {
					id = strings.TrimSpace(out)
				}
				c.bundleID[p.Bundle] = id
			}
			p.BundleID = id
		}
	}
}

// Counters returns the previous counter reading and stores cur as the new
// one, for computing rates between reads.
func (c *Collector) SwapCounters(cur map[string]IfaceCounters) (prev map[string]IfaceCounters) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev, c.counters = c.counters, cur
	return prev
}

// AddrOwners maps every local address to the interface holding it.
func AddrOwners() map[netip.Addr]string {
	out := map[netip.Addr]string{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifs {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
					out[ip.Unmap().WithZone("")] = ifi.Name
				}
			}
		}
	}
	return out
}
