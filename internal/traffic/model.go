// Package traffic builds the physical traffic view: every flow on the
// machine tied to the hardware it crosses (which NIC, which utun) and the
// software behind it (which process, which protocol and socket).
//
// The sources are separate and swappable: mihomo's connection list (rule
// matches and per-connection bytes), the macOS socket table (process
// attribution, including flows that never entered TUN), interface counters,
// and the route table. Parsers and the join logic are pure functions, tested
// against recorded macOS output; only the collectors run commands.
package traffic

import "time"

// Transport protocols a flow can use.
const (
	ProtoTCP   = "tcp"
	ProtoUDP   = "udp"
	ProtoICMP  = "icmp"
	ProtoUnix  = "unix"
	ProtoOther = "other"
)

// Application protocols guessed from the transport and port.
const (
	AppQUIC = "quic"
	AppDNS  = "dns"
)

// Socket is one row of the socket table.
type Socket struct {
	PID       int    `json:"pid"`
	Command   string `json:"command"`
	User      string `json:"user,omitempty"`
	Proto     string `json:"proto"`
	Family    string `json:"family"` // ipv4, ipv6, or unix
	Local     string `json:"local"`  // ip:port, or the path for a Unix socket
	Remote    string `json:"remote,omitempty"`
	State     string `json:"state,omitempty"` // TCP state, e.g. ESTABLISHED
	Listening bool   `json:"listening,omitempty"`
}

// Process describes the program behind a flow.
type Process struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Path       string `json:"path,omitempty"`
	Bundle     string `json:"bundle,omitempty"` // path of the enclosing .app
	BundleID   string `json:"bundle_id,omitempty"`
	ParentPID  int    `json:"parent_pid,omitempty"`
	ParentName string `json:"parent_name,omitempty"`
	Signature  string `json:"signature,omitempty"` // code-signing identity
}

// Route is a routing-table entry.
type Route struct {
	Dest    string `json:"dest"`    // CIDR
	Gateway string `json:"gateway"` // IP, or empty for an on-link route
	Flags   string `json:"flags"`
	Iface   string `json:"iface"`
}

// IfaceCounters are an interface's cumulative counters.
type IfaceCounters struct {
	Name     string `json:"name"`
	InBytes  uint64 `json:"in_bytes"`
	OutBytes uint64 `json:"out_bytes"`
	InPkts   uint64 `json:"in_packets"`
	OutPkts  uint64 `json:"out_packets"`
	InErrs   uint64 `json:"in_errors"`
	OutErrs  uint64 `json:"out_errors"`
	Drops    uint64 `json:"drops"`
}

// Conn is a mihomo connection, reduced to what the join needs.
type Conn struct {
	ID          string
	Start       time.Time
	End         *time.Time
	Network     string // tcp or udp
	Inbound     string // Tun, HTTP, Socks5, ...
	Source      string // ip:port as mihomo saw it
	Host        string
	DestIP      string
	DestPort    string
	Process     string
	ProcessPath string
	Rule        string
	RulePayload string
	Chains      []string // outbound node first, then the groups that chose it
	Upload      int64
	Download    int64
}

// Flow is one conversation, with every layer of its path.
type Flow struct {
	ID    string     `json:"id"`
	Start time.Time  `json:"start"`
	End   *time.Time `json:"end,omitempty"`

	// Software layer.
	Process  Process `json:"process"`
	Proto    string  `json:"proto"`
	App      string  `json:"app,omitempty"`    // quic, dns
	Family   string  `json:"family"`           // ipv4, ipv6, unix
	State    string  `json:"state,omitempty"`  // TCP state
	Local    string  `json:"local,omitempty"`  // local ip:port or Unix path
	Remote   string  `json:"remote,omitempty"` // remote ip:port
	Host     string  `json:"host,omitempty"`   // destination name, when known
	Listen   bool    `json:"listen,omitempty"`
	Internal bool    `json:"internal,omitempty"` // Unix-socket IPC, not network traffic

	// Routing layer.
	Proxied     bool   `json:"proxied"`
	EnteredTUN  bool   `json:"entered_tun"`
	Rule        string `json:"rule,omitempty"`
	RulePayload string `json:"rule_payload,omitempty"`
	Node        string `json:"node,omitempty"`  // DIRECT, REJECT, a node, or iface:<nic>
	Group       string `json:"group,omitempty"` // the group that chose the node

	// Hardware layer.
	Ingress string `json:"ingress,omitempty"` // the utun that captured it
	Egress  string `json:"egress,omitempty"`  // the interface it leaves through
	NextHop string `json:"next_hop,omitempty"`

	Upload       int64 `json:"upload"`
	Download     int64 `json:"download"`
	BytesUnknown bool  `json:"bytes_unknown,omitempty"` // seen only in the socket table, which has no byte counts

	Anomalies []Anomaly `json:"anomalies,omitempty"`
}

// Bytes is the flow's total traffic.
func (f Flow) Bytes() int64 { return f.Upload + f.Download }

// Anomaly kinds.
const (
	AnomalyBypassedTUN = "bypassed-tun" // went out a physical NIC without entering TUN
	AnomalyOtherVPN    = "other-vpn"    // routed through another client's tunnel
	AnomalyWrongNIC    = "wrong-nic"    // sourced from one NIC's address but routed out another
)

// Anomaly is something surprising about a flow's path.
type Anomaly struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}
