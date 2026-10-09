package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/nyaaorick/clash-mihomac/internal/client"
	"github.com/nyaaorick/clash-mihomac/internal/daemon"
	"github.com/nyaaorick/clash-mihomac/internal/instance"
	"github.com/nyaaorick/clash-mihomac/internal/rules"
)

const packsUsage = `Usage:
  mihomac packs [list]                          built-in and installed packs
  mihomac packs install <file|https-url> [--map NAME=TARGET]... [--enable] [--yes]
  mihomac packs update [NAME] [--yes]           re-download installed packs from their source URL
  mihomac packs remove <NAME> [--yes]           uninstall a community pack

Installing, updating, and removing show a preview of exactly what would change and
stop; add --yes to apply it. A pack's @placeholder targets (for example @proxy) are
mapped to your own targets with --map proxy=MyNode.
`

type mapFlag map[string]string

func (m mapFlag) String() string { return fmt.Sprint(map[string]string(m)) }
func (m mapFlag) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" || val == "" {
		return fmt.Errorf("want NAME=TARGET, got %q", v)
	}
	m[strings.TrimPrefix(k, "@")] = val
	return nil
}

func cmdPacks(args []string) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("packs "+sub, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, packsUsage) }
	name := instanceFlag(fs)
	mapping := mapFlag{}
	fs.Var(mapping, "map", "map a pack placeholder to a target, NAME=TARGET (repeatable)")
	enable := fs.Bool("enable", false, "also enable the pack")
	yes := fs.Bool("yes", false, "apply the change instead of only previewing it")
	// Positional arguments may come before or after flags.
	var pos []string
	for rest := args; len(rest) > 0; {
		fs.Parse(rest)
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	_, inst, err := resolve(*name)
	if err != nil {
		return err
	}
	set, err := currentRuleSet(inst)
	if err != nil {
		return err
	}

	var change rules.Change
	switch sub {
	case "list":
		all := set.AllPacks()
		names := set.PackNames()
		for _, n := range names {
			p := all[n]
			mark := " "
			if slices.Contains(set.Packs, n) {
				mark = "✓"
			}
			kind := "built-in"
			if _, installed := installedPack(set, n); installed {
				kind = "v" + p.Version
				if p.Author != "" {
					kind += " by " + p.Author
				}
			}
			fmt.Printf("%s %-16s %-24s %s\n", mark, n, kind, p.Description)
		}
		return nil
	case "install":
		if len(pos) != 1 {
			return errors.New("usage: mihomac packs install <file|https-url> [--map NAME=TARGET] [--enable] [--yes]")
		}
		data, source, err := readPackSource(pos[0])
		if err != nil {
			return err
		}
		p, err := rules.ParsePack(data)
		if err != nil {
			return err
		}
		if change, _, err = set.PrepareInstall(p, mapping, source, *enable); err != nil {
			return err
		}
	case "update":
		var targets []rules.Pack
		for _, p := range set.Library {
			if len(pos) == 0 || slices.Contains(pos, p.Name) {
				targets = append(targets, p)
			}
		}
		if len(targets) == 0 {
			return errors.New("no installed packs to update")
		}
		for _, old := range targets {
			if !strings.HasPrefix(old.Source, "https://") {
				fmt.Printf("%s: no source URL recorded; reinstall it with `mihomac packs install <file>`\n", old.Name)
				continue
			}
			data, _, err := readPackSource(old.Source)
			if err != nil {
				return fmt.Errorf("%s: %w", old.Name, err)
			}
			p, err := rules.ParsePack(data)
			if err != nil {
				return fmt.Errorf("%s: %w", old.Name, err)
			}
			if p.Name != old.Name {
				return fmt.Errorf("%s: the source now serves a pack named %q; refusing to update", old.Name, p.Name)
			}
			// Keep the targets the person chose for placeholders last time.
			c, _, err := set.PrepareInstall(p, previousMapping(old, p), old.Source, false)
			if err != nil {
				return fmt.Errorf("%s: %w (pass --map to set new placeholders)", old.Name, err)
			}
			if reflect.DeepEqual(c.InstallPacks[0], old) {
				fmt.Printf("%s: already up to date (v%s)\n", old.Name, old.Version)
				continue
			}
			change.InstallPacks = append(change.InstallPacks, c.InstallPacks...)
		}
	case "remove":
		if len(pos) != 1 {
			return errors.New("usage: mihomac packs remove <NAME>")
		}
		change.RemovePacks = []string{pos[0]}
	default:
		fmt.Fprint(os.Stderr, packsUsage)
		return fmt.Errorf("unknown packs command %q", sub)
	}

	if len(change.InstallPacks) == 0 && len(change.RemovePacks) == 0 {
		return nil
	}
	diff, err := set.Diff(change)
	if err != nil {
		return err
	}
	if !*yes || running(inst) { // an offline apply prints the diff itself
		fmt.Print(diff)
	}
	if !*yes {
		fmt.Println("\nThis is a preview; nothing has changed. Re-run with --yes to apply.")
		return nil
	}
	return changeRules(inst, change)
}

func installedPack(set rules.Set, name string) (rules.Pack, bool) {
	for _, p := range set.Library {
		if p.Name == name {
			return p, true
		}
	}
	return rules.Pack{}, false
}

// previousMapping recovers which target an installed pack's placeholders
// were mapped to, by lining its rules up with the freshly downloaded
// version's rules.
func previousMapping(old, fresh rules.Pack) map[string]string {
	m := map[string]string{}
	type key struct{ typ, value string }
	oldTargets := map[key]string{}
	for _, r := range old.Rules {
		oldTargets[key{r.Type, r.Value}] = r.Target
	}
	for _, r := range fresh.Rules {
		if strings.HasPrefix(r.Target, "@") {
			if t, ok := oldTargets[key{r.Type, r.Value}]; ok && t != "DIRECT" && t != "REJECT" {
				m[strings.TrimPrefix(r.Target, "@")] = t
			}
		}
	}
	for _, ph := range fresh.Placeholders() {
		if _, ok := m[strings.TrimPrefix(ph, "@")]; !ok {
			// Fall back to any previous mapping of this placeholder's rules.
			for _, r := range fresh.Rules {
				if r.Target == ph {
					if t, ok := oldTargets[key{r.Type, r.Value}]; ok {
						m[strings.TrimPrefix(ph, "@")] = t
					}
				}
			}
		}
	}
	return m
}

func readPackSource(src string) (data []byte, source string, err error) {
	if strings.HasPrefix(src, "http://") {
		return nil, "", errors.New("pack URLs must use https://")
	}
	if strings.HasPrefix(src, "https://") {
		ctx, cancel := apiCtx()
		defer cancel()
		data, err = rules.NewFetcher().Fetch(ctx, src)
		return data, src, err
	}
	f, err := os.Open(src)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	data, err = io.ReadAll(io.LimitReader(f, rules.MaxPackBytes+1))
	if err == nil && len(data) > rules.MaxPackBytes {
		err = fmt.Errorf("%s is larger than %d bytes", src, rules.MaxPackBytes)
	}
	return data, "", err
}

// currentRuleSet is the instance's rule set: the live one if it is
// running, else the saved file.
func currentRuleSet(inst instance.Instance) (rules.Set, error) {
	if !running(inst) {
		return rules.Load(inst.Path("rules.yaml"))
	}
	api, err := client.ForInstance(inst, client.TokenFull)
	if err != nil {
		return rules.Set{}, err
	}
	ctx, cancel := apiCtx()
	defer cancel()
	var v daemon.RulesView
	if err := api.Get(ctx, "/api/rules", &v); err != nil {
		return rules.Set{}, err
	}
	return v.Set, nil
}
