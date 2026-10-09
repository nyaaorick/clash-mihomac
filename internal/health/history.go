package health

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// History limits.
const (
	maxPerNode = 500
	maxAge     = 7 * 24 * time.Hour
)

// State is a node's health at a glance.
type State string

// Node states.
const (
	StateUnknown  State = "unknown"
	StateHealthy  State = "healthy"
	StateDegraded State = "degraded" // working, but recent failures
	StateDown     State = "down"
	StateBlocked  State = "blocked" // failing in a way that looks like interference
)

// History keeps recent checks per node and saves them to disk.
type History struct {
	mu    sync.Mutex
	path  string
	data  map[string][]Check
	dirty bool
	Now   func() time.Time
}

// LoadHistory reads the history at path. A missing or unreadable file is
// an empty history; the file is only ever a cache of past results.
func LoadHistory(path string) *History {
	h := &History{path: path, data: map[string][]Check{}}
	if raw, err := os.ReadFile(path); err == nil {
		var data map[string][]Check
		if json.Unmarshal(raw, &data) == nil && data != nil {
			h.data = data
			h.trim()
		}
	}
	return h
}

func (h *History) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// trim drops old checks. The caller holds h.mu (or is the constructor).
func (h *History) trim() {
	cutoff := h.now().Add(-maxAge)
	for node, cs := range h.data {
		i := 0
		for i < len(cs) && cs[i].Time.Before(cutoff) {
			i++
		}
		cs = cs[i:]
		if len(cs) > maxPerNode {
			cs = cs[len(cs)-maxPerNode:]
		}
		if len(cs) == 0 {
			delete(h.data, node)
		} else {
			h.data[node] = cs
		}
	}
}

// Record adds a check result.
func (h *History) Record(c Check) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.data[c.Node] = append(h.data[c.Node], c)
	h.dirty = true
	h.trim()
}

// Forget drops history for nodes that no longer exist.
func (h *History) Forget(keep map[string]bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for node := range h.data {
		if !keep[node] {
			delete(h.data, node)
			h.dirty = true
		}
	}
}

// Save writes the history if it changed since the last save.
func (h *History) Save() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.dirty || h.path == "" {
		return nil
	}
	raw, err := json.Marshal(h.data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(h.path), 0o700); err != nil {
		return err
	}
	tmp := h.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, h.path); err != nil {
		return err
	}
	h.dirty = false
	return nil
}

// Checks returns a node's checks, oldest first.
func (h *History) Checks(node string) []Check {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Check(nil), h.data[node]...)
}

// Nodes lists nodes that have history, sorted.
func (h *History) Nodes() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.data))
	for n := range h.data {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Summary is one node's health, derived from its history.
type Summary struct {
	Node       string    `json:"node"`
	State      State     `json:"state"`
	Since      time.Time `json:"since,omitempty"` // when the node entered this state's streak
	Reason     string    `json:"reason,omitempty"`
	Kind       Kind      `json:"kind,omitempty"`
	Last       *Check    `json:"last,omitempty"`
	Checks     int       `json:"checks"`
	Uptime24h  float64   `json:"uptime_24h"` // 0..1, -1 when there are no checks in the window
	AvgDelayMs int       `json:"avg_delay_ms,omitempty"`
}

// Summary describes a node's current health.
func (h *History) Summary(node string) Summary {
	return Summarize(node, h.Checks(node), h.now())
}

// Summarize derives a node's health from its checks, oldest first.
//
// One failure only makes a node degraded, since single failures are
// common. Two failures in a row make it down, or blocked when they look
// like interference (see Kind.Blocking).
func Summarize(node string, cs []Check, now time.Time) Summary {
	s := Summary{Node: node, State: StateUnknown, Checks: len(cs), Uptime24h: -1}
	if len(cs) == 0 {
		return s
	}
	last := cs[len(cs)-1]
	s.Last = &last

	var okN, n24, delaySum, delayN int
	for _, c := range cs {
		if now.Sub(c.Time) > 24*time.Hour {
			continue
		}
		n24++
		if c.OK {
			okN++
			delaySum += c.DelayMs
			delayN++
		}
	}
	if n24 > 0 {
		s.Uptime24h = float64(okN) / float64(n24)
	}
	if delayN > 0 {
		s.AvgDelayMs = delaySum / delayN
	}

	// The trailing run of checks that all agree on OK-ness.
	start := len(cs) - 1
	for start > 0 && cs[start-1].OK == last.OK {
		start--
	}
	s.Since = cs[start].Time
	run := len(cs) - start

	switch {
	case last.OK:
		s.State = StateHealthy
		recent := cs[max(0, len(cs)-10):]
		fails := 0
		for _, c := range recent {
			if !c.OK {
				fails++
			}
		}
		if fails*5 >= len(recent) && fails > 0 { // ≥20% of the last 10
			s.State = StateDegraded
			s.Reason = fmt.Sprintf("%d of the last %d checks failed", fails, len(recent))
		}
	case run < 2:
		s.State, s.Kind = StateDegraded, last.Kind
		s.Reason = "latest check failed: " + describe(last)
	case last.Kind.Blocking():
		s.State, s.Kind = StateBlocked, last.Kind
		s.Reason = fmt.Sprintf("%d checks in a row failed with %s: %s", run, last.Kind, last.Detail)
	default:
		s.State, s.Kind = StateDown, last.Kind
		s.Reason = fmt.Sprintf("%d checks in a row failed: %s", run, describe(last))
	}
	return s
}

func describe(c Check) string {
	if c.Detail != "" {
		return c.Detail
	}
	if c.Kind != "" {
		return string(c.Kind)
	}
	return "failed"
}

// Overview looks across all nodes for patterns a single node can't show.
func Overview(sums []Summary) []string {
	var failing, blocked, usable int
	kinds := map[Kind]int{}
	for _, s := range sums {
		switch s.State {
		case StateDown, StateBlocked:
			failing++
			kinds[s.Kind]++
			if s.State == StateBlocked {
				blocked++
			}
		case StateHealthy, StateDegraded:
			usable++
		}
	}
	var notes []string
	if failing >= 2 && usable == 0 && failing == len(sums) {
		notes = append(notes, "Every node is failing. That usually means a problem on your side (no internet, a firewall, a captive portal) rather than all of them being blocked at once.")
	}
	if k, n := dominant(kinds); n >= 2 && n == failing && failing < len(sums) && k != KindNone {
		notes = append(notes, fmt.Sprintf("%d nodes are failing the same way (%s) while others work, which points at interference on that route.", n, k))
	}
	if blocked > 0 && blocked < failing {
		notes = append(notes, "Some failures look like blocking and some like plain outages; check each node's reason.")
	}
	return notes
}

func dominant(m map[Kind]int) (Kind, int) {
	var best Kind
	n := 0
	for k, v := range m {
		if v > n || v == n && k < best {
			best, n = k, v
		}
	}
	return best, n
}
