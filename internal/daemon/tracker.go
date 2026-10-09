package daemon

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Conn is a connection as Clash Mihomac shows it: live or recently closed.
type Conn struct {
	ID          string     `json:"id"`
	Start       time.Time  `json:"start"`
	End         *time.Time `json:"end,omitempty"`
	Network     string     `json:"network"`
	Inbound     string     `json:"inbound"` // HTTP, HTTPS, Socks5, Tun, ...
	Source      string     `json:"source"`
	Host        string     `json:"host"`
	DestIP      string     `json:"dest_ip"`
	DestPort    string     `json:"dest_port"`
	Process     string     `json:"process"`
	ProcessPath string     `json:"process_path"`
	Rule        string     `json:"rule"`
	RulePayload string     `json:"rule_payload"`
	Chains      []string   `json:"chains"`
	Upload      int64      `json:"upload"`
	Download    int64      `json:"download"`
	Error       string     `json:"error,omitempty"` // set when the core failed to connect
}

// Destination is the host (or IP) and port the connection went to.
func (c Conn) Destination() string {
	h := c.Host
	if h == "" {
		h = c.DestIP
	}
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return h + ":" + c.DestPort
}

// LogLine is one core log message.
type LogLine struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

// Tracker remembers live connections and a window of closed ones, since
// mihomo itself forgets a connection as soon as it closes.
type Tracker struct {
	mu        sync.Mutex
	active    map[string]*Conn
	closed    []*Conn // oldest first
	logs      []LogLine
	maxClosed int
	maxLogs   int
	failures  int
	now       func() time.Time
}

// NewTracker returns an empty tracker.
func NewTracker() *Tracker {
	return &Tracker{active: map[string]*Conn{}, maxClosed: 1000, maxLogs: 500, now: time.Now}
}

// Update replaces the live set with a fresh controller snapshot. Anything
// that disappeared is recorded as closed.
func (t *Tracker) Update(snap []ctrlConn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	seen := make(map[string]bool, len(snap))
	for _, cc := range snap {
		seen[cc.ID] = true
		c := t.active[cc.ID]
		if c == nil {
			c = &Conn{ID: cc.ID}
			t.active[cc.ID] = c
		}
		m := cc.Metadata
		host := m.Host
		if host == "" {
			host = m.SniffHost
		}
		*c = Conn{
			ID: cc.ID, Start: cc.Start, Network: m.Network, Inbound: m.Type,
			Source: m.SourceIP + ":" + m.SourcePort, Host: host, DestIP: firstNonEmpty(m.DestinationIP, m.RemoteDest), DestPort: m.DestinationPort,
			Process: m.Process, ProcessPath: m.ProcessPath, Rule: cc.Rule, RulePayload: cc.RulePayload,
			Chains: cc.Chains, Upload: cc.Upload, Download: cc.Download,
		}
	}
	now := t.now()
	for id, c := range t.active {
		if seen[id] {
			continue
		}
		delete(t.active, id)
		end := now
		c.End = &end
		t.closed = append(t.closed, c)
	}
	if over := len(t.closed) - t.maxClosed; over > 0 {
		t.closed = slices.Delete(t.closed, 0, over)
	}
}

// Reset forgets live connections (e.g. when the core restarts), keeping
// them as closed.
func (t *Tracker) Reset() { t.Update(nil) }

// List returns connections newest first, filtered by a case-insensitive
// substring of host, IP, process, rule, or route.
func (t *Tracker) List(query string, limit int) []Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	all := make([]Conn, 0, len(t.active)+len(t.closed))
	for _, c := range t.active {
		all = append(all, *c)
	}
	for _, c := range t.closed {
		all = append(all, *c)
	}
	slices.SortFunc(all, func(a, b Conn) int { return b.Start.Compare(a.Start) })

	q := strings.ToLower(query)
	out := make([]Conn, 0, min(limit, len(all)))
	for _, c := range all {
		if q != "" && !strings.Contains(strings.ToLower(strings.Join([]string{
			c.Host, c.DestIP, c.Process, c.Rule, c.RulePayload, strings.Join(c.Chains, " "),
		}, " ")), q) {
			continue
		}
		out = append(out, c)
		if len(out) == limit {
			break
		}
	}
	return out
}

// Get returns one connection by ID.
func (t *Tracker) Get(id string) (Conn, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.active[id]; ok {
		return *c, true
	}
	for _, c := range t.closed {
		if c.ID == id {
			return *c, true
		}
	}
	return Conn{}, false
}

// AddLog records a core log line. A failed dial never appears in the
// controller's connection list, so it is recorded here as a failed
// connection: those are the requests people most want to diagnose.
func (t *Tracker) AddLog(level, msg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.logs = append(t.logs, LogLine{Time: now, Level: level, Message: msg})
	if over := len(t.logs) - t.maxLogs; over > 0 {
		t.logs = slices.Delete(t.logs, 0, over)
	}
	if c, ok := parseDialError(msg); ok {
		t.failures++
		c.ID = fmt.Sprintf("failed-%06d", t.failures)
		c.Start, c.End = now, &now
		t.closed = append(t.closed, &c)
		if over := len(t.closed) - t.maxClosed; over > 0 {
			t.closed = slices.Delete(t.closed, 0, over)
		}
	}
}

// dialErrorRE matches mihomo's failed-dial warning, e.g.
//
//	[TCP] dial iface:en0 (match DomainSuffix/example.com) 127.0.0.1:61261(curl) --> example.com:443 error: dial tcp 198.18.0.178:443: i/o timeout
var (
	dialErrorRE = regexp.MustCompile(`^\[(TCP|UDP)\] dial (\S+) \(match ([^/)]*)/?([^)]*)\) (\S+?)(?:\(([^)]*)\))? --> (\S+):(\d+) error: (.*)$`)
	dialAddrRE  = regexp.MustCompile(`dial (?:tcp|udp)[46]? \[?([0-9a-fA-F.:]+?)\]?:\d+`)
)

func parseDialError(msg string) (Conn, bool) {
	m := dialErrorRE.FindStringSubmatch(msg)
	if m == nil {
		return Conn{}, false
	}
	c := Conn{
		Network: strings.ToLower(m[1]), Chains: []string{m[2]}, Rule: m[3], RulePayload: m[4],
		Source: m[5], Process: m[6], Host: strings.Trim(m[7], "[]"), DestPort: m[8], Error: m[9],
	}
	if a := dialAddrRE.FindAllStringSubmatch(m[9], -1); len(a) > 0 {
		c.DestIP = a[len(a)-1][1]
	}
	return c, true
}

// LogsFor returns log lines that mention c's host or IP during its life.
func (t *Tracker) LogsFor(c Conn) []LogLine {
	t.mu.Lock()
	defer t.mu.Unlock()
	from := c.Start.Add(-2 * time.Second)
	to := t.now()
	if c.End != nil {
		to = c.End.Add(5 * time.Second)
	}
	var out []LogLine
	for _, l := range t.logs {
		if l.Time.Before(from) || l.Time.After(to) {
			continue
		}
		if (c.Host != "" && strings.Contains(l.Message, c.Host)) || (c.DestIP != "" && strings.Contains(l.Message, c.DestIP)) {
			out = append(out, l)
		}
	}
	return out
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
