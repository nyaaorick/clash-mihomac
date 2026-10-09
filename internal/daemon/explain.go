package daemon

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/nyaaorick/clash-mihomac/internal/rules"
)

// Explanation answers "why did this connection go here?".
type Explanation struct {
	Summary string        `json:"summary"`
	Path    []PathStep    `json:"path"` // app → rule → outbound → destination
	Rule    *MatchedRule  `json:"rule,omitempty"`
	Out     OutboundRoute `json:"outbound"`
}

// PathStep is one hop in the end-to-end view.
type PathStep struct {
	Kind   string `json:"kind"` // app, rule, outbound, destination
	Label  string `json:"label"`
	Detail string `json:"detail,omitempty"`
}

// MatchedRule is the rule a connection matched, with its origin.
type MatchedRule struct {
	Position int          `json:"position"` // 1-based position in the final rule list
	Line     string       `json:"line"`
	Source   rules.Source `json:"source"`
}

// OutboundRoute is how the connection left the machine.
type OutboundRoute struct {
	Node      string `json:"node"`
	Group     string `json:"group,omitempty"`
	Interface string `json:"interface,omitempty"`
	Blocked   bool   `json:"blocked,omitempty"`
}

// Explain builds a plain-language explanation for c, given the core's rule
// list (in match order), the provenance of each rule, and the interface
// DIRECT traffic uses by default.
func Explain(c Conn, ctrlRules []ctrlRule, sources []rules.Source, defaultIface string) Explanation {
	var e Explanation
	var b strings.Builder

	who := c.Process
	if who == "" {
		who = "An unidentified process"
		if c.Inbound != "" && !strings.EqualFold(c.Inbound, "tun") {
			who += " (it reached the proxy port, so macOS couldn't attribute it)"
		}
	}
	fmt.Fprintf(&b, "%s connected to %s", who, c.Destination())
	if c.Host != "" && c.DestIP != "" && c.DestIP != c.Host {
		fmt.Fprintf(&b, " (%s)", c.DestIP)
	}
	b.WriteString(". ")
	e.Path = append(e.Path, PathStep{Kind: "app", Label: firstNonEmpty(c.Process, "unknown process"), Detail: c.ProcessPath})

	for i, r := range ctrlRules {
		if r.Type != c.Rule || r.Payload != c.RulePayload {
			continue
		}
		m := &MatchedRule{Position: i + 1, Line: ruleLine(r)}
		if i < len(sources) {
			m.Source = sources[i]
		}
		e.Rule = m
		break
	}
	switch {
	case strings.EqualFold(c.Rule, "Match"):
		fmt.Fprintf(&b, "No other rule matched, so the final MATCH rule sent it to %s. ", lastOr(c.Chains, "?"))
		e.Path = append(e.Path, PathStep{Kind: "rule", Label: "MATCH (fallback)"})
	case e.Rule != nil:
		fmt.Fprintf(&b, "It matched rule #%d `%s`, which comes from %s. ", e.Rule.Position, e.Rule.Line, describeSource(e.Rule.Source))
		e.Path = append(e.Path, PathStep{Kind: "rule", Label: e.Rule.Line, Detail: describeSource(e.Rule.Source)})
	default:
		fmt.Fprintf(&b, "It matched a %s rule (%s). ", c.Rule, c.RulePayload)
		e.Path = append(e.Path, PathStep{Kind: "rule", Label: c.Rule + "," + c.RulePayload})
	}

	e.Out = outbound(c.Chains, defaultIface)
	switch {
	case e.Out.Blocked:
		b.WriteString("It was blocked.")
	case e.Out.Node == "DIRECT":
		fmt.Fprintf(&b, "It went out directly through the default route (%s).", firstNonEmpty(e.Out.Interface, "unknown interface"))
	case strings.HasPrefix(e.Out.Node, rules.IfacePrefix):
		fmt.Fprintf(&b, "It went out directly through %s.", e.Out.Interface)
	case e.Out.Group != "":
		fmt.Fprintf(&b, "The %s group picked node %s.", e.Out.Group, e.Out.Node)
	default:
		fmt.Fprintf(&b, "It went through node %s.", e.Out.Node)
	}
	if c.Error != "" {
		fmt.Fprintf(&b, " The connection failed: %s.", c.Error)
		if isFakeIP(c.DestIP) {
			fmt.Fprintf(&b, " %s is a fake-ip address handed out by a proxy's DNS (fake-ip mode); it only works through that proxy's TUN, never out a physical interface. Resolve this domain with real DNS (Clash Mihomac does this for domain rules that target an interface) or switch the other client to redir-host.", c.DestIP)
		}
	}
	label := e.Out.Node
	if e.Out.Interface != "" {
		label += " via " + e.Out.Interface
	}
	e.Path = append(e.Path,
		PathStep{Kind: "outbound", Label: label, Detail: e.Out.Group},
		PathStep{Kind: "destination", Label: c.Destination(), Detail: c.DestIP})

	e.Summary = b.String()
	return e
}

func outbound(chains []string, defaultIface string) OutboundRoute {
	if len(chains) == 0 {
		return OutboundRoute{Node: "?"}
	}
	o := OutboundRoute{Node: chains[0]}
	if len(chains) > 1 {
		o.Group = chains[len(chains)-1]
	}
	switch {
	case strings.HasPrefix(o.Node, "REJECT"):
		o.Blocked = true
	case o.Node == "DIRECT":
		o.Interface = defaultIface
	case strings.HasPrefix(o.Node, rules.IfacePrefix):
		o.Interface = strings.TrimPrefix(o.Node, rules.IfacePrefix)
	}
	return o
}

var fakeIPRange = netip.MustParsePrefix("198.18.0.0/15")

func isFakeIP(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && fakeIPRange.Contains(a)
}

func describeSource(s rules.Source) string {
	switch s.Kind {
	case "user":
		d := "your rule " + s.Name
		if s.Note != "" {
			d += " (" + s.Note + ")"
		}
		return d
	case "bypass":
		return "the built-in local/private bypass (" + s.Note + ")"
	case "pack":
		return "the " + s.Name + " rule pack"
	case "config":
		return fmt.Sprintf("rule #%d in your mihomo config file", s.Index)
	}
	return "an unknown source"
}

func ruleLine(r ctrlRule) string {
	if r.Payload == "" {
		return r.Type + "," + r.Proxy
	}
	return r.Type + "," + r.Payload + "," + r.Proxy
}

func lastOr(ss []string, def string) string {
	if len(ss) == 0 {
		return def
	}
	return ss[len(ss)-1]
}
