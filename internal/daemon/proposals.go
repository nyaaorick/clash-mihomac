package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/rules"
)

// Proposal statuses.
const (
	StatusPending  = "pending"
	StatusApplied  = "applied"
	StatusRejected = "rejected"
	StatusFailed   = "failed"
)

// Proposal is a rule change waiting for a person to confirm it. The MCP
// server can only create proposals; applying one needs the GUI or CLI.
type Proposal struct {
	ID      string       `json:"id"`
	Created time.Time    `json:"created"`
	Origin  string       `json:"origin"` // "agent" (MCP) or "user"
	Summary string       `json:"summary"`
	Change  rules.Change `json:"change"`
	Diff    string       `json:"diff"`
	Status  string       `json:"status"`
	Error   string       `json:"error,omitempty"`
	Decided *time.Time   `json:"decided,omitempty"`
}

// Proposals is a small persisted list of proposals.
type Proposals struct {
	mu   sync.Mutex
	path string
	list []*Proposal
}

// LoadProposals reads proposals from path, if it exists.
func LoadProposals(path string) *Proposals {
	p := &Proposals{path: path}
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, &p.list)
	}
	return p
}

// Create records a new pending proposal with its dry-run diff.
func (p *Proposals) Create(origin, summary string, change rules.Change, diff string) (*Proposal, error) {
	b := make([]byte, 4)
	rand.Read(b)
	pr := &Proposal{
		ID: hex.EncodeToString(b), Created: time.Now(), Origin: origin,
		Summary: summary, Change: change, Diff: diff, Status: StatusPending,
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.list = append(p.list, pr)
	if len(p.list) > 100 {
		p.list = p.list[len(p.list)-100:]
	}
	return pr, p.save()
}

// List returns proposals newest first.
func (p *Proposals) List() []Proposal {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Proposal, len(p.list))
	for i, pr := range p.list {
		out[len(p.list)-1-i] = *pr
	}
	return out
}

// Decide applies or rejects a pending proposal. apply is called only when
// applying; its error marks the proposal failed.
func (p *Proposals) Decide(id string, accept bool, apply func(rules.Change) error) (Proposal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := slices.IndexFunc(p.list, func(pr *Proposal) bool { return pr.ID == id })
	if i < 0 {
		return Proposal{}, fmt.Errorf("no proposal %q", id)
	}
	pr := p.list[i]
	if pr.Status != StatusPending {
		return *pr, fmt.Errorf("proposal %s is already %s", id, pr.Status)
	}
	now := time.Now()
	pr.Decided = &now
	switch {
	case !accept:
		pr.Status = StatusRejected
	default:
		if err := apply(pr.Change); err != nil {
			pr.Status, pr.Error = StatusFailed, err.Error()
			p.save()
			return *pr, err
		}
		pr.Status = StatusApplied
	}
	return *pr, p.save()
}

func (p *Proposals) save() error {
	if p.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(p.list, "", "  ")
	if err != nil {
		return err
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.path)
}

// ErrAgentForbidden is returned when an agent-scoped caller tries to do
// something only a person may do.
var ErrAgentForbidden = errors.New("agents may only propose changes; a person must apply them in the GUI or CLI")
