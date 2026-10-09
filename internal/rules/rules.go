// Package rules is Clash Mihomac's routing model: the rules a user manages
// through the CLI, GUI, and MCP, compiled into mihomo rules.
//
// Compiled rules are ordered:
//
//  1. user rules (so a user can send an intranet CIDR out a specific NIC)
//  2. the built-in bypass (localhost, .local, private and link-local ranges)
//  3. enabled rule packs
//  4. rules from the user's mihomo config
//
// Every compiled rule keeps its provenance so diagnostics can explain which
// rule matched a connection and where that rule came from.
package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Rule types a user can write.
const (
	TypeDomain        = "domain"
	TypeDomainSuffix  = "domain-suffix"
	TypeDomainKeyword = "domain-keyword"
	TypeIPCIDR        = "ip-cidr"
	TypeProcessName   = "process-name"
	TypeProcessPath   = "process-path"
	TypeApp           = "app" // an .app bundle; matches every process inside it
)

// Types lists the rule types in display order.
var Types = []string{TypeDomain, TypeDomainSuffix, TypeDomainKeyword, TypeIPCIDR, TypeProcessName, TypeProcessPath, TypeApp}

// IfacePrefix marks a target that sends traffic DIRECT out a specific
// network interface, e.g. "iface:en1".
const IfacePrefix = "iface:"

// Rule routes matching traffic to a target.
type Rule struct {
	Type   string `yaml:"type" json:"type"`
	Value  string `yaml:"value" json:"value"`
	Target string `yaml:"target" json:"target"`
	Note   string `yaml:"note,omitempty" json:"note,omitempty"`
}

// InternalDNS resolves internal domains with internal DNS servers,
// optionally out a specific interface.
type InternalDNS struct {
	Domains   []string `yaml:"domains" json:"domains"`
	Servers   []string `yaml:"servers" json:"servers"`
	Interface string   `yaml:"interface,omitempty" json:"interface,omitempty"`
}

// Set is everything stored in an instance's rules.yaml.
type Set struct {
	Packs       []string      `yaml:"packs" json:"packs"`
	Rules       []Rule        `yaml:"rules" json:"rules"`
	InternalDNS []InternalDNS `yaml:"internal_dns,omitempty" json:"internal_dns,omitempty"`
}

// Load reads a rule set. A missing file is an empty set.
func Load(path string) (Set, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Set{}, nil
	}
	if err != nil {
		return Set{}, err
	}
	var s Set
	if err := yaml.Unmarshal(data, &s); err != nil {
		return Set{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return s, s.Validate()
}

// Save validates and atomically writes a rule set.
func Save(path string, s Set) error {
	if err := s.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var (
	ifaceRE  = regexp.MustCompile(`^[a-z]+[0-9]+$`)
	domainRE = regexp.MustCompile(`^[A-Za-z0-9*_-]+(\.[A-Za-z0-9_-]+)*\.?$`)
)

// Validate checks that every rule can be compiled safely.
func (s Set) Validate() error {
	for _, p := range s.Packs {
		if _, ok := packs[p]; !ok {
			return fmt.Errorf("unknown rule pack %q (known: %s)", p, strings.Join(PackNames(), ", "))
		}
	}
	for i, r := range s.Rules {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	for i, d := range s.InternalDNS {
		if len(d.Domains) == 0 || len(d.Servers) == 0 {
			return fmt.Errorf("internal_dns %d: needs at least one domain and one server", i+1)
		}
		for _, dom := range d.Domains {
			if !domainRE.MatchString(dom) {
				return fmt.Errorf("internal_dns %d: invalid domain %q", i+1, dom)
			}
		}
		for _, srv := range d.Servers {
			if _, err := netip.ParseAddr(srv); err != nil {
				return fmt.Errorf("internal_dns %d: server %q must be an IP address", i+1, srv)
			}
		}
		if d.Interface != "" && !ifaceRE.MatchString(d.Interface) {
			return fmt.Errorf("internal_dns %d: invalid interface %q", i+1, d.Interface)
		}
	}
	return nil
}

// Validate checks one rule.
func (r Rule) Validate() error {
	if r.Value == "" || strings.ContainsAny(r.Value, ",\n\r") {
		return fmt.Errorf("value %q must be non-empty and contain no commas or newlines", r.Value)
	}
	switch r.Type {
	case TypeDomain, TypeDomainSuffix:
		if !domainRE.MatchString(r.Value) {
			return fmt.Errorf("invalid domain %q", r.Value)
		}
	case TypeDomainKeyword, TypeProcessName:
	case TypeIPCIDR:
		if _, err := netip.ParsePrefix(r.Value); err != nil {
			return fmt.Errorf("invalid CIDR %q", r.Value)
		}
	case TypeProcessPath:
		if !filepath.IsAbs(r.Value) {
			return fmt.Errorf("process path %q must be absolute", r.Value)
		}
	case TypeApp:
		if !filepath.IsAbs(r.Value) || !strings.HasSuffix(strings.TrimSuffix(r.Value, "/"), ".app") {
			return fmt.Errorf("app %q must be an absolute path to a .app bundle", r.Value)
		}
	default:
		return fmt.Errorf("unknown rule type %q (known: %s)", r.Type, strings.Join(Types, ", "))
	}
	return validateTarget(r.Target)
}

func validateTarget(t string) error {
	if t == "" || strings.ContainsAny(t, ",\n\r") {
		return fmt.Errorf("target %q must be non-empty and contain no commas or newlines", t)
	}
	if name, ok := strings.CutPrefix(t, IfacePrefix); ok && !ifaceRE.MatchString(name) {
		return fmt.Errorf("invalid interface in target %q", t)
	}
	return nil
}

// Source says where a compiled rule came from.
type Source struct {
	Kind  string `json:"kind"`            // "user", "bypass", "pack", or "config"
	Name  string `json:"name,omitempty"`  // pack name, or "#n" for user rules
	Note  string `json:"note,omitempty"`  // the user's note, if any
	Index int    `json:"index,omitempty"` // 1-based index within its source
}

// Compiled is a rule set ready to merge into a mihomo config.
type Compiled struct {
	Rules            []string         // mihomo rule lines, excluding config rules
	Sources          []Source         // provenance for each entry in Rules
	Proxies          []map[string]any // interface-bound DIRECT outbounds
	NameserverPolicy map[string]any
}

// Compile turns a validated set into mihomo rules.
func Compile(s Set) (Compiled, error) {
	if err := s.Validate(); err != nil {
		return Compiled{}, err
	}
	c := Compiled{NameserverPolicy: map[string]any{}}
	ifaces := map[string]bool{}

	add := func(r Rule, src Source) {
		c.Rules = append(c.Rules, line(r))
		c.Sources = append(c.Sources, src)
		if name, ok := strings.CutPrefix(r.Target, IfacePrefix); ok {
			ifaces[name] = true
		}
	}

	for i, r := range s.Rules {
		add(r, Source{Kind: "user", Name: fmt.Sprintf("#%d", i+1), Note: r.Note, Index: i + 1})
	}
	for i, r := range Bypass {
		add(r, Source{Kind: "bypass", Note: r.Note, Index: i + 1})
	}
	for _, p := range s.Packs {
		for i, r := range packs[p].Rules {
			add(r, Source{Kind: "pack", Name: p, Index: i + 1})
		}
	}

	// A domain sent out a specific interface is also resolved through that
	// interface's own DHCP-provided DNS. Otherwise another resolver (the
	// default route's, or another proxy's fake-ip DNS) can return addresses
	// that aren't reachable from that interface. Explicit internal_dns
	// entries below take precedence.
	for _, r := range s.Rules {
		name, ok := strings.CutPrefix(r.Target, IfacePrefix)
		if !ok {
			continue
		}
		switch r.Type {
		case TypeDomain:
			c.NameserverPolicy[r.Value] = []string{"dhcp://" + name}
		case TypeDomainSuffix:
			c.NameserverPolicy["+."+r.Value] = []string{"dhcp://" + name}
		}
	}

	for _, d := range s.InternalDNS {
		servers := make([]string, len(d.Servers))
		for i, srv := range d.Servers {
			servers[i] = srv
			if d.Interface != "" {
				servers[i] += "#" + d.Interface
			}
		}
		for _, dom := range d.Domains {
			c.NameserverPolicy["+."+strings.TrimPrefix(dom, "+.")] = servers
		}
	}

	names := make([]string, 0, len(ifaces))
	for n := range ifaces {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c.Proxies = append(c.Proxies, map[string]any{"name": IfacePrefix + n, "type": "direct", "interface-name": n})
	}
	return c, nil
}

// line renders a rule as a mihomo rule line.
func line(r Rule) string {
	switch r.Type {
	case TypeDomain:
		return "DOMAIN," + r.Value + "," + r.Target
	case TypeDomainSuffix:
		return "DOMAIN-SUFFIX," + r.Value + "," + r.Target
	case TypeDomainKeyword:
		return "DOMAIN-KEYWORD," + r.Value + "," + r.Target
	case TypeIPCIDR:
		kind := "IP-CIDR"
		if strings.Contains(r.Value, ":") {
			kind = "IP-CIDR6"
		}
		return kind + "," + r.Value + "," + r.Target + ",no-resolve"
	case TypeProcessName:
		return "PROCESS-NAME," + r.Value + "," + r.Target
	case TypeProcessPath:
		return "PROCESS-PATH," + r.Value + "," + r.Target
	case TypeApp:
		return "PROCESS-PATH-REGEX,^" + regexp.QuoteMeta(strings.TrimSuffix(r.Value, "/")) + "/," + r.Target
	}
	panic("unvalidated rule type " + r.Type)
}

// Targets returns every target referenced by the set's user rules, for
// checking against the proxies and groups in the user's config.
func (s Set) Targets() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range s.Rules {
		if !seen[r.Target] {
			seen[r.Target] = true
			out = append(out, r.Target)
		}
	}
	return out
}
