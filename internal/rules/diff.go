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
}

// Apply returns s with c applied. s is not modified. It fails if a removed
// rule doesn't exist or the result is invalid.
func (s Set) Apply(c Change) (Set, error) {
	out := Set{
		Packs:       slices.Clone(s.Packs),
		Rules:       slices.Clone(s.Rules),
		InternalDNS: slices.Clone(s.InternalDNS),
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
