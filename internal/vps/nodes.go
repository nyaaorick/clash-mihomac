package vps

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"go.yaml.in/yaml/v3"
)

// Imported is a node added from a share link, a subscription, or a server
// set up by Clash Mihomac. Nodes are kept apart from the user's own config
// file so the user's file is never rewritten (and loses no comments).
type Imported struct {
	Node    `yaml:",inline"`
	Machine string    `yaml:"machine,omitempty" json:"machine,omitempty"` // the managed server it belongs to
	Added   time.Time `yaml:"added" json:"added"`
}

type nodeFile struct {
	Nodes []Imported `yaml:"nodes"`
}

// MaxImportedNodes bounds the imported list.
const MaxImportedNodes = 1000

// LoadNodes reads imported nodes; a missing file is an empty list.
func LoadNodes(path string) ([]Imported, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f nodeFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return f.Nodes, nil
}

// SaveNodes writes imported nodes atomically (mode 0600: they hold credentials).
func SaveNodes(path string, nodes []Imported) error {
	data, err := yaml.Marshal(nodeFile{Nodes: nodes})
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

// MergeNodes adds nodes to list, replacing an existing node of the same
// name that belongs to the same machine (a re-import after a credential
// rotation) and renaming other clashes. taken lists names already used
// elsewhere, such as the user's own config.
func MergeNodes(list []Imported, add []Imported, taken map[string]bool) ([]Imported, error) {
	out := append([]Imported(nil), list...)
	names := map[string]bool{}
	for k := range taken {
		names[k] = true
	}
	for _, n := range out {
		names[n.Name] = true
	}
	for _, a := range add {
		replaced := false
		if a.Machine != "" {
			for i := range out {
				if out[i].Machine == a.Machine && out[i].Name == a.Name {
					a.Added = out[i].Added
					out[i], replaced = a, true
					break
				}
			}
		}
		if replaced {
			continue
		}
		base, n := a.Name, 1
		for names[a.Name] {
			n++
			a.Name = fmt.Sprintf("%s-%d", base, n)
		}
		a.Proxy["name"] = a.Name
		names[a.Name] = true
		out = append(out, a)
	}
	if len(out) > MaxImportedNodes {
		return nil, fmt.Errorf("too many imported nodes (limit %d)", MaxImportedNodes)
	}
	return out, nil
}

// Proxies returns the nodes as mihomo proxy entries.
func Proxies(list []Imported) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, n := range list {
		out[i] = n.Proxy
	}
	return out
}
