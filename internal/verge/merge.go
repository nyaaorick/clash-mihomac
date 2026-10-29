package verge

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"go.yaml.in/yaml/v3"
)

// Patch is what Clash Mihomac adds to Verge's config: rules ahead of the
// profile's own, extra outbounds (imported nodes and interface-bound
// DIRECT proxies), failover groups, and per-domain DNS policy.
type Patch struct {
	Rules            []string
	Proxies          []map[string]any
	Groups           []map[string]any
	NameserverPolicy map[string]any
}

// Keys Clash Mihomac owns in the global Merge profile. Verge's merge step
// understands prepend-/append- keys for rules, proxies, and proxy-groups;
// other keys replace the profile's own wholesale, which is why the DNS
// policy is not written here (it would wipe the profile's DNS settings).
const (
	keyPrependRules = "prepend-rules"
	keyAppendProxy  = "append-proxies"
	keyAppendGroups = "append-proxy-groups"
)

// ManagedKeys lists the Merge keys Clash Mihomac rewrites.
var ManagedKeys = []string{keyPrependRules, keyAppendProxy, keyAppendGroups}

const mergeHeader = "# Written by Clash Mihomac. The keys prepend-rules, append-proxies, and\n# append-proxy-groups are replaced on every change; anything else in this\n# file is kept. Edit your rules in Clash Mihomac, not here.\n"

// ProfilesFile is Verge's profile index.
const ProfilesFile = "profiles.yaml"

// MergeFile returns the path of the global Merge profile, the file Verge
// merges into every profile. The index names it; "Merge.yaml" is the
// default when the index has no such entry yet.
func (d Dir) MergeFile() (string, error) {
	data, err := os.ReadFile(d.Path(ProfilesFile))
	if err != nil {
		return "", fmt.Errorf("read Clash Verge's profile index: %w", err)
	}
	var doc struct {
		Items []struct {
			UID  string `yaml:"uid"`
			Type string `yaml:"type"`
			File string `yaml:"file"`
		} `yaml:"items"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("parse %s: %w", ProfilesFile, err)
	}
	for _, it := range doc.Items {
		if it.UID == "Merge" && it.Type == "merge" && it.File != "" {
			return d.Path("profiles", it.File), nil
		}
	}
	return d.Path("profiles", "Merge.yaml"), nil
}

// WriteMerge rewrites the managed keys of the Merge file and keeps every
// other key. Comments in the existing file are lost (the file is parsed
// and re-serialized), which is why the header says what owns it.
func WriteMerge(path string, p Patch) error {
	doc := map[string]any{}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if doc == nil {
			doc = map[string]any{}
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return err
	}
	for _, k := range ManagedKeys {
		delete(doc, k)
	}
	if len(p.Rules) > 0 {
		doc[keyPrependRules] = toAnyStrings(p.Rules)
	}
	if len(p.Proxies) > 0 {
		doc[keyAppendProxy] = toAnyMaps(p.Proxies)
	}
	if len(p.Groups) > 0 {
		doc[keyAppendGroups] = toAnyMaps(p.Groups)
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if len(doc) == 0 {
		out = nil
	}
	return writeAtomic(path, append([]byte(mergeHeader), out...), 0o644)
}

// ReadMerge returns the managed keys currently in the Merge file: what
// Clash Mihomac wrote last time. A missing file is an empty patch.
func ReadMerge(path string) (Patch, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Patch{}, nil
	}
	if err != nil {
		return Patch{}, err
	}
	doc := map[string]any{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Patch{}, fmt.Errorf("parse %s: %w", path, err)
	}
	var p Patch
	for _, v := range toAnyList(doc[keyPrependRules]) {
		if s, ok := v.(string); ok {
			p.Rules = append(p.Rules, s)
		}
	}
	p.Proxies = listOfMaps(doc[keyAppendProxy])
	p.Groups = listOfMaps(doc[keyAppendGroups])
	return p, nil
}

// Strip returns a copy of cfg without an earlier patch: its rules (by
// exact text), and its proxies and groups (by exact content, so a
// profile's own entry that merely shares a name with an earlier one is
// kept). Verge's runtime config already contains the Merge file once
// Verge has applied it, so building on it without stripping would
// duplicate every entry.
func Strip(cfg map[string]any, prev Patch) map[string]any {
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		out[k] = v
	}
	if len(prev.Rules) > 0 {
		drop := map[string]bool{}
		for _, r := range prev.Rules {
			drop[r] = true
		}
		kept := []any{}
		for _, r := range toAnyList(out["rules"]) {
			if s, ok := r.(string); !ok || !drop[s] {
				kept = append(kept, r)
			}
		}
		out["rules"] = kept
	}
	for key, prevItems := range map[string][]map[string]any{"proxies": prev.Proxies, "proxy-groups": prev.Groups} {
		if len(prevItems) == 0 {
			continue
		}
		kept := []any{}
		for _, it := range toAnyList(out[key]) {
			if m, ok := it.(map[string]any); ok && sameItem(m, prevItems) {
				continue
			}
			kept = append(kept, it)
		}
		out[key] = kept
	}
	return out
}

// sameItem reports whether m equals one of items, compared after a YAML
// round trip so that int/float and ordering differences from
// serialization don't matter.
func sameItem(m map[string]any, items []map[string]any) bool {
	a, err := yaml.Marshal(m)
	if err != nil {
		return false
	}
	for _, it := range items {
		if b, err := yaml.Marshal(it); err == nil && string(a) == string(b) {
			return true
		}
	}
	return false
}

// Apply returns a copy of cfg with the patch applied the way Verge's
// merge step would, plus the DNS policy: rules go first, proxies and
// groups are appended (an outbound or group whose name the config already
// uses is skipped and reported), and nameserver-policy entries are added to the
// existing DNS section. The result is what the daemon hands mihomo as a
// hot reload, so it mirrors what Verge will produce on its next apply.
func Apply(cfg map[string]any, p Patch) (out map[string]any, skipped []string) {
	out = make(map[string]any, len(cfg)+4)
	for k, v := range cfg {
		out[k] = v
	}

	if len(p.Rules) > 0 {
		existing, _ := out["rules"].([]any)
		rules := make([]any, 0, len(p.Rules)+len(existing))
		rules = append(rules, toAnyStrings(p.Rules)...)
		out["rules"] = append(rules, existing...)
	}

	if len(p.Proxies) > 0 {
		existing, _ := out["proxies"].([]any)
		used := map[string]bool{}
		for _, m := range listOfMaps(existing) {
			if n, _ := m["name"].(string); n != "" {
				used[n] = true
			}
		}
		proxies := append([]any{}, existing...)
		for _, m := range p.Proxies {
			n, _ := m["name"].(string)
			if n == "" || used[n] {
				skipped = append(skipped, n)
				continue
			}
			used[n] = true
			proxies = append(proxies, m)
		}
		out["proxies"] = proxies
	}

	if len(p.Groups) > 0 {
		existing, _ := out["proxy-groups"].([]any)
		used := map[string]bool{}
		for _, m := range listOfMaps(existing) {
			if n, _ := m["name"].(string); n != "" {
				used[n] = true
			}
		}
		for _, m := range listOfMaps(out["proxies"]) {
			if n, _ := m["name"].(string); n != "" {
				used[n] = true
			}
		}
		groups := append([]any{}, existing...)
		for _, g := range p.Groups {
			n, _ := g["name"].(string)
			if n == "" || used[n] {
				skipped = append(skipped, n)
				continue
			}
			used[n] = true
			groups = append(groups, g)
		}
		out["proxy-groups"] = groups
	}

	if len(p.NameserverPolicy) > 0 {
		dns := map[string]any{}
		if cur, ok := out["dns"].(map[string]any); ok {
			for k, v := range cur {
				dns[k] = v
			}
		}
		policy := map[string]any{}
		if cur, ok := dns["nameserver-policy"].(map[string]any); ok {
			for k, v := range cur {
				policy[k] = v
			}
		}
		keys := make([]string, 0, len(p.NameserverPolicy))
		for k := range p.NameserverPolicy {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			policy[k] = p.NameserverPolicy[k]
		}
		dns["nameserver-policy"] = policy
		if _, ok := dns["enable"]; !ok {
			dns["enable"] = true
		}
		out["dns"] = dns
	}
	sort.Strings(skipped)
	return out, skipped
}

func toAnyStrings(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func toAnyMaps(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

func toAnyList(v any) []any {
	items, _ := v.([]any)
	return items
}
