package vps

import (
	"context"
	"strings"
	"sync"
)

// FakeServer is a scripted server for tests. Commands are matched against
// handlers in order; the first whose Match is a substring of the command
// answers it. Files written with `cat > path` land in Files.
type FakeServer struct {
	mu       sync.Mutex
	Handlers []FakeHandler
	Files    map[string]string
	Log      []string // every command run, in order
	Stdin    map[string][]byte
	Key      string // host-key fingerprint to present
	// Accept decides which logins succeed; nil accepts every Target.
	Accept func(Target) error
	Dials  []Target
}

// FakeHandler answers commands containing Match.
type FakeHandler struct {
	Match string
	Reply func(cmd string, stdin []byte) Result
}

// Reply is shorthand for a handler with a fixed answer.
func Reply(match, stdout string, exit int) FakeHandler {
	return FakeHandler{Match: match, Reply: func(string, []byte) Result { return Result{Stdout: stdout, Exit: exit} }}
}

// Dial implements Dialer.
func (f *FakeServer) Dial(_ context.Context, t Target) (Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Dials = append(f.Dials, t)
	key := f.Key
	if key == "" {
		key = "SHA256:fakehostkey"
	}
	if t.HostKey != "" && t.HostKey != key {
		return nil, &HostKeyError{Want: t.HostKey, Got: key}
	}
	if f.Accept != nil {
		if err := f.Accept(t); err != nil {
			return nil, err
		}
	}
	return &fakeConn{f: f, key: key}, nil
}

type fakeConn struct {
	f   *FakeServer
	key string
}

func (c *fakeConn) HostKey() string { return c.key }
func (c *fakeConn) Close() error    { return nil }

func (c *fakeConn) Run(_ context.Context, cmd string, stdin []byte) (Result, error) {
	f := c.f
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Log = append(f.Log, cmd)
	if f.Files == nil {
		f.Files = map[string]string{}
		f.Stdin = map[string][]byte{}
	}
	// Commands arrive wrapped as sh -c '<quoted>'; undo one level of
	// quoting so handlers match what the script itself says.
	norm := strings.ReplaceAll(cmd, `'\''`, `'`)
	// File uploads: `umask 077 && cat > 'path' && chmod ...`
	if stdin != nil {
		if i := strings.Index(norm, "cat > '"); i >= 0 {
			rest := norm[i+len("cat > '"):]
			if j := strings.Index(rest, "'"); j >= 0 {
				f.Files[rest[:j]] = string(stdin)
			}
		}
	}
	for _, h := range f.Handlers {
		if strings.Contains(norm, h.Match) || strings.Contains(cmd, h.Match) {
			return h.Reply(norm, stdin), nil
		}
	}
	return Result{}, nil
}

// Ran reports whether any command containing sub was run.
func (f *FakeServer) Ran(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.Log {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}
