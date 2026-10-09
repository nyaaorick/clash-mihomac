package rules

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

// Pack files are community-written, so they are untrusted input: strict
// parsing, size limits, and a restricted set of targets. A pack can send
// traffic DIRECT or REJECT it, or name a placeholder (@name) that the person
// installing it maps to one of their own nodes. A pack can never name a
// node, interface, or group itself.

// Limits on a pack file.
const (
	MaxPackBytes = 1 << 20
	MaxPackRules = 5000
)

var (
	packNameRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	packVersionRE = regexp.MustCompile(`^\d{1,4}\.\d{1,4}\.\d{1,4}$`)
	placeholderRE = regexp.MustCompile(`^@[a-z][a-z0-9-]{0,29}$`)
)

// ParsePack reads and validates a pack file. Rule targets may still be
// placeholders; call Resolve before installing.
func ParsePack(data []byte) (Pack, error) {
	if len(data) > MaxPackBytes {
		return Pack{}, fmt.Errorf("pack file is larger than %d bytes", MaxPackBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p Pack
	if err := dec.Decode(&p); err != nil {
		return Pack{}, fmt.Errorf("parse pack: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Pack{}, errors.New("parse pack: a pack file holds a single document")
	}
	if p.Source != "" {
		return Pack{}, errors.New("a pack file can't set source; it is recorded when the pack is installed")
	}
	if err := p.checkMetadata(true); err != nil {
		return Pack{}, err
	}
	if len(p.Rules) == 0 {
		return Pack{}, errors.New("pack has no rules")
	}
	if len(p.Rules) > MaxPackRules {
		return Pack{}, fmt.Errorf("pack has %d rules; the limit is %d", len(p.Rules), MaxPackRules)
	}
	for i, r := range p.Rules {
		if err := checkText("note", r.Note, 120); err != nil {
			return Pack{}, fmt.Errorf("rule %d: %w", i+1, err)
		}
		check := r
		switch {
		case r.Target == "DIRECT" || r.Target == "REJECT":
		case placeholderRE.MatchString(r.Target):
			check.Target = "DIRECT" // validate the rest of the rule
		default:
			return Pack{}, fmt.Errorf("rule %d: target %q isn't allowed in a pack; use DIRECT, REJECT, or a placeholder like @proxy", i+1, r.Target)
		}
		if err := check.Validate(); err != nil {
			return Pack{}, fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return p, nil
}

func (p Pack) checkMetadata(requireVersion bool) error {
	if !packNameRE.MatchString(p.Name) {
		return fmt.Errorf("pack name %q must be 1-40 lowercase letters, digits, or dashes", p.Name)
	}
	if _, builtin := packs[p.Name]; builtin {
		return fmt.Errorf("pack name %q is taken by a built-in pack", p.Name)
	}
	if p.Version == "" && requireVersion {
		return errors.New("pack needs a version like 1.0.0")
	}
	if p.Version != "" && !packVersionRE.MatchString(p.Version) {
		return fmt.Errorf("pack version %q must look like 1.2.3", p.Version)
	}
	if err := checkText("author", p.Author, 80); err != nil {
		return err
	}
	if err := checkText("description", p.Description, 300); err != nil {
		return err
	}
	if p.Source != "" {
		if err := checkText("source", p.Source, 500); err != nil {
			return err
		}
	}
	return nil
}

func checkText(field, s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("%s is longer than %d characters", field, max)
	}
	for _, r := range s {
		if r < ' ' || r == 0x7f {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}

// Placeholders lists the @names in a pack's targets, sorted.
func (p Pack) Placeholders() []string {
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if strings.HasPrefix(r.Target, "@") {
			seen[r.Target] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Resolve returns a copy of p with every placeholder replaced using
// mapping (keys with or without the leading @). Mapped targets are the
// installer's choice, so they may be any valid target.
func (p Pack) Resolve(mapping map[string]string) (Pack, error) {
	norm := map[string]string{}
	for k, v := range mapping {
		norm["@"+strings.TrimPrefix(k, "@")] = v
	}
	out := p
	out.Rules = slices.Clone(p.Rules)
	for i, r := range out.Rules {
		if !strings.HasPrefix(r.Target, "@") {
			continue
		}
		t, ok := norm[r.Target]
		if !ok {
			return Pack{}, fmt.Errorf("pack %s needs a target for %s (e.g. --map %s=DIRECT)", p.Name, r.Target, strings.TrimPrefix(r.Target, "@"))
		}
		if err := validateTarget(t); err != nil {
			return Pack{}, fmt.Errorf("target for %s: %w", r.Target, err)
		}
		out.Rules[i].Target = t
	}
	return out, nil
}

// validateLibrary checks installed packs: unique, well-formed, concrete.
func validateLibrary(lib []Pack) error {
	seen := map[string]bool{}
	for _, p := range lib {
		if err := p.checkMetadata(false); err != nil {
			return fmt.Errorf("installed pack: %w", err)
		}
		if seen[p.Name] {
			return fmt.Errorf("pack %q is installed twice", p.Name)
		}
		seen[p.Name] = true
		if len(p.Rules) > MaxPackRules {
			return fmt.Errorf("pack %s has %d rules; the limit is %d", p.Name, len(p.Rules), MaxPackRules)
		}
		for i, r := range p.Rules {
			if err := r.Validate(); err != nil {
				return fmt.Errorf("pack %s rule %d: %w", p.Name, i+1, err)
			}
		}
	}
	return nil
}

// pack finds an enabled-or-installable pack by name: built in or installed.
func (s Set) pack(name string) (Pack, bool) {
	if p, ok := packs[name]; ok {
		p.Name = name
		return p, true
	}
	for _, p := range s.Library {
		if p.Name == name {
			return p, true
		}
	}
	return Pack{}, false
}

// PackNames lists built-in and installed pack names, sorted.
func (s Set) PackNames() []string {
	names := PackNames()
	for _, p := range s.Library {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	return names
}

// AllPacks returns every pack available to s, built in or installed.
func (s Set) AllPacks() map[string]Pack {
	out := Packs()
	for _, p := range s.Library {
		out[p.Name] = p
	}
	return out
}

// Conflicts lists rules in p that match the same thing as a rule with
// higher precedence (the user's rules, the built-in bypass, or an enabled
// pack ahead of it) but send it somewhere else, so the pack's rule would
// never take effect.
func (s Set) Conflicts(p Pack) []string {
	type key struct{ typ, value string }
	winner := map[key]string{}
	note := func(r Rule, from string) {
		k := key{r.Type, strings.ToLower(r.Value)}
		if _, ok := winner[k]; !ok {
			winner[k] = r.Target + "|" + from
		}
	}
	for _, r := range s.Rules {
		note(r, "your rule")
	}
	for _, r := range Bypass {
		note(r, "the built-in bypass")
	}
	for _, name := range s.Packs {
		if name == p.Name {
			break
		}
		if other, ok := s.pack(name); ok {
			for _, r := range other.Rules {
				note(r, "the "+name+" pack")
			}
		}
	}
	var out []string
	for _, r := range p.Rules {
		if w, ok := winner[key{r.Type, strings.ToLower(r.Value)}]; ok {
			target, from, _ := strings.Cut(w, "|")
			if target != r.Target {
				out = append(out, fmt.Sprintf("%s %s → %s is overridden by %s (→ %s)", r.Type, r.Value, r.Target, from, target))
			}
		}
	}
	return out
}

// Fetcher downloads pack files over HTTPS.
type Fetcher struct{ Client *http.Client }

// NewFetcher returns a Fetcher that only talks to public addresses, so a
// pack URL can't be used to probe localhost or the local network.
func NewFetcher() Fetcher {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || isCGNAT(ip) {
				return fmt.Errorf("refusing to connect to non-public address %s", ip)
			}
			return nil
		},
	}
	return Fetcher{Client: &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext, Proxy: nil, TLSHandshakeTimeout: 10 * time.Second},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("refusing to follow a redirect to a non-HTTPS URL")
			}
			return nil
		},
	}}
}

func isCGNAT(ip netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

// Fetch downloads a pack file, which must be served over HTTPS and be no
// larger than MaxPackBytes.
func (f Fetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%q is not an https:// URL", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download pack: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download pack: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxPackBytes+1))
	if err != nil {
		return nil, fmt.Errorf("download pack: %w", err)
	}
	if len(data) > MaxPackBytes {
		return nil, fmt.Errorf("pack file is larger than %d bytes", MaxPackBytes)
	}
	return data, nil
}

// PrepareInstall builds the change that installs (or updates) p. source is
// where p came from, kept so the pack can be updated later; enable also
// turns the pack on.
func (s Set) PrepareInstall(p Pack, mapping map[string]string, source string, enable bool) (Change, Pack, error) {
	resolved, err := p.Resolve(mapping)
	if err != nil {
		return Change{}, Pack{}, err
	}
	resolved.Source = source
	if err := validateLibrary([]Pack{resolved}); err != nil {
		return Change{}, Pack{}, err
	}
	c := Change{InstallPacks: []Pack{resolved}}
	if enable {
		c.EnablePacks = []string{resolved.Name}
	}
	return c, resolved, nil
}
