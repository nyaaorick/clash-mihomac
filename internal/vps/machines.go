package vps

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Machine is one managed server. Nothing secret is stored here: no
// password, and no share link (it can be re-read from the server). The SSH
// private key lives beside this file in keys/, mode 0600, until a native
// component can keep it in the macOS Keychain.
type Machine struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Host    string    `json:"host"`
	Port    int       `json:"port"`
	User    string    `json:"user"`
	HostKey string    `json:"host_key"`
	HasKey  bool      `json:"has_key"` // an SSH key is stored, so the server can be managed without a password
	Region  string    `json:"region,omitempty"`
	Added   time.Time `json:"added"`

	NodeName string `json:"node_name,omitempty"` // the node imported from this server
	NodePort int    `json:"node_port,omitempty"`

	Quota   Quota      `json:"quota"`
	Traffic TrafficAcc `json:"traffic"`
	Last    *Check     `json:"last,omitempty"`
}

// Quota is a monthly traffic allowance.
type Quota struct {
	GB       int `json:"gb,omitempty"`        // 0 means unlimited or unknown
	ResetDay int `json:"reset_day,omitempty"` // day of month the allowance resets; default 1
}

// TrafficAcc accumulates a server's traffic across reboots (the kernel's
// counters restart at zero when it does).
type TrafficAcc struct {
	Period string `json:"period"` // billing period, e.g. 2026-10
	Bytes  uint64 `json:"bytes"`  // rx + tx used in this period
	LastRx uint64 `json:"last_rx"`
	LastTx uint64 `json:"last_tx"`
}

// Check is the result of the last health check of a machine.
type Check struct {
	Time    time.Time `json:"time"`
	State   State     `json:"state"`
	Reasons []string  `json:"reasons,omitempty"`
	Error   string    `json:"error,omitempty"`
	Metrics *Metrics  `json:"metrics,omitempty"`
}

// Account adds the traffic since the last reading to the machine's period
// total. A counter that went backwards means a reboot: the whole new value
// is counted. Returns the updated accumulator.
func (a TrafficAcc) Account(m Metrics, q Quota, now time.Time) TrafficAcc {
	period := BillingPeriod(now, q.ResetDay)
	if a.Period != period {
		a = TrafficAcc{Period: period, LastRx: m.RxTotal, LastTx: m.TxTotal}
		return a // the new period starts counting from this reading
	}
	delta := func(cur, last uint64) uint64 {
		if cur < last {
			return cur
		}
		return cur - last
	}
	a.Bytes += delta(m.RxTotal, a.LastRx) + delta(m.TxTotal, a.LastTx)
	a.LastRx, a.LastTx = m.RxTotal, m.TxTotal
	return a
}

// BillingPeriod names the period `now` falls in, for a quota that resets on
// resetDay of each month (1-28; anything else means the 1st).
func BillingPeriod(now time.Time, resetDay int) string {
	if resetDay < 1 || resetDay > 28 {
		resetDay = 1
	}
	y, mo := now.Year(), now.Month()
	if now.Day() < resetDay {
		mo--
		if mo == 0 {
			mo, y = 12, y-1
		}
	}
	return fmt.Sprintf("%04d-%02d", y, int(mo))
}

// Store keeps machines in a directory: machines.json and keys/.
type Store struct {
	Dir string
	mu  sync.Mutex
}

var idRE = regexp.MustCompile(`^m[0-9a-f]{6}$`)

func (s *Store) path() string { return filepath.Join(s.Dir, "machines.json") }

func (s *Store) load() ([]Machine, error) {
	data, err := os.ReadFile(s.path())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ms []Machine
	if err := json.Unmarshal(data, &ms); err != nil {
		return nil, fmt.Errorf("read %s: %w", s.path(), err)
	}
	return ms, nil
}

func (s *Store) save(ms []Machine) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ms, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path())
}

// List returns the machines, sorted by name.
func (s *Store) List() ([]Machine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ms, err := s.load()
	sort.Slice(ms, func(i, j int) bool { return strings.ToLower(ms[i].Name) < strings.ToLower(ms[j].Name) })
	return ms, err
}

// Get returns one machine by ID or name.
func (s *Store) Get(idOrName string) (Machine, error) {
	ms, err := s.List()
	if err != nil {
		return Machine{}, err
	}
	for _, m := range ms {
		if m.ID == idOrName || strings.EqualFold(m.Name, idOrName) {
			return m, nil
		}
	}
	return Machine{}, fmt.Errorf("no machine %q", idOrName)
}

// Add stores a new machine, assigning its ID.
func (s *Store) Add(m Machine) (Machine, error) {
	if !proxyNameRE.MatchString(m.Name) {
		return Machine{}, fmt.Errorf("machine name %q must be 1-40 letters, digits, spaces, dots, dashes, or underscores", m.Name)
	}
	if !hostRE.MatchString(m.Host) {
		return Machine{}, fmt.Errorf("invalid server address %q", m.Host)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ms, err := s.load()
	if err != nil {
		return Machine{}, err
	}
	for _, x := range ms {
		if strings.EqualFold(x.Name, m.Name) {
			return Machine{}, fmt.Errorf("a machine named %q already exists", m.Name)
		}
		if x.Host == m.Host && x.Port == m.Port {
			return Machine{}, fmt.Errorf("%s:%d is already managed as %q", m.Host, m.Port, x.Name)
		}
	}
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Machine{}, err
	}
	m.ID = "m" + hex.EncodeToString(b[:])
	if m.Port == 0 {
		m.Port = 22
	}
	if m.User == "" {
		m.User = "root"
	}
	if m.Added.IsZero() {
		m.Added = time.Now()
	}
	return m, s.save(append(ms, m))
}

// Update changes a machine in place.
func (s *Store) Update(id string, fn func(*Machine)) (Machine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ms, err := s.load()
	if err != nil {
		return Machine{}, err
	}
	for i := range ms {
		if ms[i].ID == id {
			fn(&ms[i])
			ms[i].ID = id
			return ms[i], s.save(ms)
		}
	}
	return Machine{}, fmt.Errorf("no machine %q", id)
}

// Remove forgets a machine and deletes its stored key.
func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ms, err := s.load()
	if err != nil {
		return err
	}
	for i := range ms {
		if ms[i].ID == id {
			ms = append(ms[:i], ms[i+1:]...)
			if idRE.MatchString(id) {
				os.Remove(s.keyPath(id))
			}
			return s.save(ms)
		}
	}
	return fmt.Errorf("no machine %q", id)
}

func (s *Store) keyPath(id string) string { return filepath.Join(s.Dir, "keys", id) }

// SaveKey stores a machine's private key (mode 0600).
func (s *Store) SaveKey(id string, pem []byte) error {
	if !idRE.MatchString(id) {
		return fmt.Errorf("invalid machine id %q", id)
	}
	if err := os.MkdirAll(filepath.Join(s.Dir, "keys"), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(s.keyPath(id), pem, 0o600); err != nil {
		return err
	}
	_, err := s.Update(id, func(m *Machine) { m.HasKey = true })
	return err
}

// LoadKey reads a machine's private key.
func (s *Store) LoadKey(id string) ([]byte, error) {
	if !idRE.MatchString(id) {
		return nil, fmt.Errorf("invalid machine id %q", id)
	}
	return os.ReadFile(s.keyPath(id))
}

// Target builds the SSH target for a machine, using its stored key.
func (s *Store) Target(m Machine) (Target, error) {
	t := Target{Host: m.Host, Port: m.Port, User: m.User, HostKey: m.HostKey}
	if m.HasKey {
		key, err := s.LoadKey(m.ID)
		if err != nil {
			return Target{}, fmt.Errorf("the stored SSH key for %s is missing: %w", m.Name, err)
		}
		t.KeyPEM = key
	}
	return t, nil
}
