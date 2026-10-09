package rules

import (
	"fmt"
	"slices"
	"strings"
)

// Change is a proposed edit to a rule set. It is what the MCP server and
// GUI submit; nothing is applied until a person confirms it.
type Change struct {
	Add          []Rule   `json:"add,omitempty"`
	Remove       []Rule   `json:"remove,omitempty"` // matched on type, value, and target
	EnablePacks  []string `json:"enable_packs,omitempty"`
	DisablePacks []string `json:"disable_packs,omitempty"`
	// InstallPacks adds or replaces installed packs (same name = update);
	// RemovePacks uninstalls them, disabling them first.
	InstallPacks []Pack   `json:"install_packs,omitempty"`
	RemovePacks  []string `json:"remove_packs,omitempty"`
}

// Apply returns s with c applied. s is not modified. It fails if a removed
// rule doesn't exist or the result is invalid.
func (s Set) Apply(c Change) (Set, error) {
	out := Set{
		Packs:       slices.Clone(s.Packs),
		Rules:       slices.Clone(s.Rules),
		InternalDNS: slices.Clone(s.InternalDNS),
		Library:     slices.Clone(s.Library),
	}
	for _, name := range c.RemovePacks {
		i := slices.IndexFunc(out.Library, func(p Pack) bool { return p.Name == name })
		if i < 0 {
			return Set{}, fmt.Errorf("pack %q isn't installed (built-in packs can be disabled, not removed)", name)
		}
		out.Library = slices.Delete(out.Library, i, i+1)
		out.Packs = slices.DeleteFunc(out.Packs, func(p string) bool { return p == name })
	}
	for _, p := range c.InstallPacks {
		if i := slices.IndexFunc(out.Library, func(x Pack) bool { return x.Name == p.Name }); i >= 0 {
			out.Library[i] = p
		} else {
			out.Library = append(out.Library, p)
		}
	}
	for _, r := range c.Remove {
		i := slices.IndexFunc(out.Rules, func(x Rule) bool {
			return x.Type == r.Type && x.Value == r.Value && x.Target == r.Target
		})
		if i < 0 {
			return Set{}, fmt.Errorf("no rule %s to remove", Describe(r))
		}
		out.Rules = slices.Delete(out.Rules, i, i+1)
	}
	// New rules go first so they take precedence over existing ones.
	out.Rules = append(slices.Clone(c.Add), out.Rules...)
	for _, p := range c.EnablePacks {
		if !slices.Contains(out.Packs, p) {
			out.Packs = append(out.Packs, p)
		}
	}
	out.Packs = slices.DeleteFunc(out.Packs, func(p string) bool { return slices.Contains(c.DisablePacks, p) })
	return out, out.Validate()
}

// Diff renders a human-readable dry run of applying c to s.
func (s Set) Diff(c Change) (string, error) {
	next, err := s.Apply(c)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, name := range c.RemovePacks {
		fmt.Fprintf(&b, "- remove pack %s\n", name)
	}
	for _, p := range c.InstallPacks {
		writePackDiff(&b, s, p)
	}
	for _, r := range c.Add {
		fmt.Fprintf(&b, "+ %s\n", Describe(r))
	}
	for _, r := range c.Remove {
		fmt.Fprintf(&b, "- %s\n", Describe(r))
	}
	for _, p := range c.EnablePacks {
		if !slices.Contains(s.Packs, p) {
			fmt.Fprintf(&b, "+ pack %s\n", p)
		}
	}
	for _, p := range c.DisablePacks {
		if slices.Contains(s.Packs, p) {
			fmt.Fprintf(&b, "- pack %s\n", p)
		}
	}
	for _, name := range c.EnablePacks {
		if p, ok := next.pack(name); ok && !slices.Contains(s.Packs, name) {
			for _, msg := range next.Conflicts(p) {
				fmt.Fprintf(&b, "! %s: %s\n", name, msg)
			}
		}
	}
	if b.Len() == 0 {
		return "(no changes)\n", nil
	}
	fmt.Fprintf(&b, "\n%d user rules, %d packs after this change.\n", len(next.Rules), len(next.Packs))
	return b.String(), nil
}

// Describe renders a rule for people.
func Describe(r Rule) string {
	return fmt.Sprintf("%s %s → %s", r.Type, r.Value, r.Target)
}

// maxDiffRules caps how many of a pack's rules a diff lists.
const maxDiffRules = 25

func writePackDiff(b *strings.Builder, before Set, p Pack) {
	byline := ""
	if p.Author != "" {
		byline = " by " + p.Author
	}
	old, installed := Pack{}, false
	for _, x := range before.Library {
		if x.Name == p.Name {
			old, installed = x, true
		}
	}
	if !installed {
		fmt.Fprintf(b, "+ install pack %s %s%s (%d rules)\n", p.Name, p.Version, byline, len(p.Rules))
	} else {
		added, removed := ruleDelta(old.Rules, p.Rules)
		fmt.Fprintf(b, "~ update pack %s %s → %s%s (+%d −%d rules)\n", p.Name, old.Version, p.Version, byline, added, removed)
	}
	if p.Description != "" {
		fmt.Fprintf(b, "    %s\n", p.Description)
	}
	for i, r := range p.Rules {
		if i == maxDiffRules {
			fmt.Fprintf(b, "    … and %d more rules\n", len(p.Rules)-maxDiffRules)
			break
		}
		fmt.Fprintf(b, "    %s\n", Describe(r))
	}
}

func ruleDelta(old, next []Rule) (added, removed int) {
	has := func(rs []Rule, r Rule) bool {
		return slices.ContainsFunc(rs, func(x Rule) bool { return x.Type == r.Type && x.Value == r.Value && x.Target == r.Target })
	}
	for _, r := range next {
		if !has(old, r) {
			added++
		}
	}
	for _, r := range old {
		if !has(next, r) {
			removed++
		}
	}
	return
}
