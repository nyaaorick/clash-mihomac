package traffic

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"
)

// History limits.
const (
	DefaultRetention = 24 * time.Hour
	maxHistoryFlows  = 50000
)

// Store keeps live flows and a bounded history of finished ones, so the
// view can show either "now" or "the last few hours". History lives in a
// local file that only the user can read; nothing is sent anywhere.
type Store struct {
	mu        sync.Mutex
	path      string
	retention time.Duration
	active    map[string]Flow
	done      []Flow
	pending   []Flow // finished since the last flush
	now       func() time.Time
}

// OpenStore loads the history at path (if any), dropping flows older than
// retention. A zero retention means DefaultRetention.
func OpenStore(path string, retention time.Duration) *Store {
	return OpenStoreAt(path, retention, time.Now)
}

// OpenStoreAt is OpenStore with an explicit clock, for tests.
func OpenStoreAt(path string, retention time.Duration, clock func() time.Time) *Store {
	if retention <= 0 {
		retention = DefaultRetention
	}
	s := &Store{path: path, retention: retention, active: map[string]Flow{}, now: clock}
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var fl Flow
			if json.Unmarshal(sc.Bytes(), &fl) == nil && fl.ID != "" {
				s.done = append(s.done, fl)
			}
		}
		s.expire()
	}
	return s
}

// Observe records the flows currently open. Flows that were open at the last
// call and are gone now are finished: they move into history.
func (s *Store) Observe(flows []Flow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	seen := make(map[string]bool, len(flows))
	for _, f := range flows {
		if f.Listen {
			continue
		}
		seen[f.ID] = true
		if f.End != nil { // mihomo already reports it closed
			if _, wasActive := s.active[f.ID]; wasActive || !s.has(f.ID) {
				s.finish(f)
			}
			delete(s.active, f.ID)
			continue
		}
		s.active[f.ID] = f
	}
	for id, f := range s.active {
		if seen[id] {
			continue
		}
		end := now
		f.End = &end
		s.finish(f)
		delete(s.active, id)
	}
	s.expire()
}

func (s *Store) has(id string) bool {
	for i := len(s.done) - 1; i >= 0 && i >= len(s.done)-2000; i-- {
		if s.done[i].ID == id {
			return true
		}
	}
	return false
}

func (s *Store) finish(f Flow) {
	if f.Bytes() == 0 && f.BytesUnknown && len(f.Anomalies) == 0 {
		return // an idle socket-table entry says nothing worth keeping
	}
	s.done = append(s.done, f)
	s.pending = append(s.pending, f)
}

// expire drops history past the retention period or the size cap.
func (s *Store) expire() {
	cutoff := s.now().Add(-s.retention)
	s.done = slices.DeleteFunc(s.done, func(f Flow) bool { return f.End != nil && f.End.Before(cutoff) })
	if over := len(s.done) - maxHistoryFlows; over > 0 {
		s.done = s.done[over:]
	}
}

// Live returns the flows open right now, biggest first.
func (s *Store) Live() []Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Flow, 0, len(s.active))
	for _, f := range s.active {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes() != out[j].Bytes() {
			return out[i].Bytes() > out[j].Bytes()
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Since returns flows that were open at any time since t: finished ones
// that ended after it, and everything still open.
func (s *Store) Since(t time.Time) []Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Flow
	for _, f := range s.done {
		if f.End == nil || !f.End.Before(t) {
			out = append(out, f)
		}
	}
	for _, f := range s.active {
		out = append(out, f)
	}
	return out
}

// Flush appends newly finished flows to the history file. It compacts the
// file when it has accumulated much more than the retained history.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" || len(s.pending) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, fl := range s.pending {
		if err := enc.Encode(fl); err != nil {
			f.Close()
			return err
		}
	}
	s.pending = s.pending[:0]
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if info, err := os.Stat(s.path); err == nil && info.Size() > int64(maxHistoryFlows)*600 {
		return s.compactLocked()
	}
	return nil
}

// Compact rewrites the history file with only the retained flows.
func (s *Store) Compact() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.compactLocked()
}

func (s *Store) compactLocked() error {
	if s.path == "" {
		return nil
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, fl := range s.done {
		if err := enc.Encode(fl); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Clear forgets all history, including the file.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done, s.pending = nil, nil
	if s.path == "" {
		return nil
	}
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
