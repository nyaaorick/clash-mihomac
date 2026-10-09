package rules

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Failover group types. Mihomo does the actual switching; a group here is
// a validated, declarative description of it that rules can target.
const (
	GroupFallback    = "fallback"     // the first healthy member, in order
	GroupURLTest     = "url-test"     // the fastest member, with hysteresis
	GroupLoadBalance = "load-balance" // spread connections across healthy members
)

// GroupTypes lists the group types in display order.
var GroupTypes = []string{GroupFallback, GroupURLTest, GroupLoadBalance}

// Load-balance strategies.
var strategies = []string{"consistent-hashing", "round-robin", "sticky-sessions"}

// Defaults and limits for health-check settings.
const (
	DefaultGroupURL      = "https://www.gstatic.com/generate_204"
	DefaultGroupInterval = 300 // seconds
	minGroupInterval     = 30
)

// Group is a multi-node failover group.
type Group struct {
	Name    string   `yaml:"name" json:"name"`
	Type    string   `yaml:"type" json:"type"`
	Members []string `yaml:"members" json:"members"` // nodes or groups from the user's config
	URL     string   `yaml:"url,omitempty" json:"url,omitempty"`
	// Interval is seconds between health checks; Timeout is milliseconds.
	Interval int `yaml:"interval,omitempty" json:"interval,omitempty"`
	Timeout  int `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	// Tolerance (url-test only) is how many ms faster another member must be
	// before the group switches to it, so it doesn't flap between near-equal nodes.
	Tolerance int `yaml:"tolerance,omitempty" json:"tolerance,omitempty"`
	// Strategy (load-balance only).
	Strategy string `yaml:"strategy,omitempty" json:"strategy,omitempty"`
	// MaxFailed is how many failed checks in a row mark a member unhealthy.
	MaxFailed int `yaml:"max_failed,omitempty" json:"max_failed,omitempty"`
}

var groupNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,39}$`)

var reservedNames = []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}

// Validate checks one group.
func (g Group) Validate() error {
	if !groupNameRE.MatchString(g.Name) {
		return fmt.Errorf("group name %q must be 1-40 letters, digits, spaces, dots, dashes, or underscores", g.Name)
	}
	if slices.Contains(reservedNames, strings.ToUpper(g.Name)) || strings.HasPrefix(g.Name, IfacePrefix) {
		return fmt.Errorf("group name %q is reserved", g.Name)
	}
	if !slices.Contains(GroupTypes, g.Type) {
		return fmt.Errorf("group %s: unknown type %q (known: %s)", g.Name, g.Type, strings.Join(GroupTypes, ", "))
	}
	if len(g.Members) < 2 || len(g.Members) > 100 {
		return fmt.Errorf("group %s: needs between 2 and 100 members, has %d", g.Name, len(g.Members))
	}
	seen := map[string]bool{}
	for _, m := range g.Members {
		if m == "" || strings.ContainsAny(m, ",\n\r") || len(m) > 200 {
			return fmt.Errorf("group %s: invalid member %q", g.Name, m)
		}
		if m == g.Name {
			return fmt.Errorf("group %s can't contain itself", g.Name)
		}
		if seen[m] {
			return fmt.Errorf("group %s: member %q is listed twice", g.Name, m)
		}
		seen[m] = true
	}
	if g.URL != "" {
		u, err := url.Parse(g.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return fmt.Errorf("group %s: health-check url %q must be an http(s) URL", g.Name, g.URL)
		}
	}
	if g.Interval != 0 && (g.Interval < minGroupInterval || g.Interval > 86400) {
		return fmt.Errorf("group %s: interval must be %d to 86400 seconds", g.Name, minGroupInterval)
	}
	if g.Timeout != 0 && (g.Timeout < 500 || g.Timeout > 30000) {
		return fmt.Errorf("group %s: timeout must be 500 to 30000 ms", g.Name)
	}
	if g.Tolerance < 0 || g.Tolerance > 5000 {
		return fmt.Errorf("group %s: tolerance must be 0 to 5000 ms", g.Name)
	}
	if g.Tolerance != 0 && g.Type != GroupURLTest {
		return fmt.Errorf("group %s: tolerance only applies to %s groups", g.Name, GroupURLTest)
	}
	if g.Strategy != "" {
		if g.Type != GroupLoadBalance {
			return fmt.Errorf("group %s: strategy only applies to %s groups", g.Name, GroupLoadBalance)
		}
		if !slices.Contains(strategies, g.Strategy) {
			return fmt.Errorf("group %s: unknown strategy %q (known: %s)", g.Name, g.Strategy, strings.Join(strategies, ", "))
		}
	}
	if g.MaxFailed < 0 || g.MaxFailed > 20 {
		return fmt.Errorf("group %s: max_failed must be 0 to 20", g.Name)
	}
	return nil
}

func validateGroups(gs []Group) error {
	seen := map[string]bool{}
	for _, g := range gs {
		if err := g.Validate(); err != nil {
			return err
		}
		if seen[g.Name] {
			return fmt.Errorf("group %q is defined twice", g.Name)
		}
		seen[g.Name] = true
	}
	for _, g := range gs {
		for _, m := range g.Members {
			if seen[m] {
				return fmt.Errorf("group %s contains group %s; groups made here can only contain nodes and groups from your config", g.Name, m)
			}
		}
	}
	return nil
}

// config renders the group as a mihomo proxy-group.
func (g Group) config() map[string]any {
	members := make([]any, len(g.Members))
	for i, m := range g.Members {
		members[i] = m
	}
	cfg := map[string]any{
		"name": g.Name, "type": g.Type, "proxies": members,
		"url": firstNonEmpty(g.URL, DefaultGroupURL), "interval": orInt(g.Interval, DefaultGroupInterval),
		"lazy": false,
	}
	if g.Timeout > 0 {
		cfg["timeout"] = g.Timeout
	}
	if g.MaxFailed > 0 {
		cfg["max-failed-times"] = g.MaxFailed
	}
	if g.Type == GroupURLTest && g.Tolerance > 0 {
		cfg["tolerance"] = g.Tolerance
	}
	if g.Type == GroupLoadBalance {
		cfg["strategy"] = firstNonEmpty(g.Strategy, "consistent-hashing")
	}
	return cfg
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func orInt(v, def int) int {
	if v != 0 {
		return v
	}
	return def
}

// Describe renders a group for people.
func (g Group) Describe() string {
	extra := ""
	switch g.Type {
	case GroupURLTest:
		if g.Tolerance > 0 {
			extra = fmt.Sprintf(", switch when %d ms faster", g.Tolerance)
		}
	case GroupLoadBalance:
		extra = ", " + firstNonEmpty(g.Strategy, "consistent-hashing")
	}
	return fmt.Sprintf("%s (%s of %s; check every %d s%s)", g.Name, g.Type, strings.Join(g.Members, ", "), orInt(g.Interval, DefaultGroupInterval), extra)
}
