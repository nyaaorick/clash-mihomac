package vps

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// maxLogLines bounds a session log held in memory.
const maxLogLines = 2000

// LogLine is one line of a setup session log.
type LogLine struct {
	Time time.Time `json:"time"`
	Text string    `json:"text"`
}

// SessionLog records what a setup did. Every line is redacted before it is
// stored, so passwords, keys, and share links never reach the log.
type SessionLog struct {
	mu    sync.Mutex
	red   *Redactor
	lines []LogLine
	file  *os.File
	now   func() time.Time
}

// NewSessionLog starts a log that hides the given redactor's secrets. If path
// is not empty the log is also written there (mode 0600).
func NewSessionLog(red *Redactor, path string) (*SessionLog, error) {
	l := &SessionLog{red: red, now: time.Now}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		l.file = f
	}
	return l, nil
}

// Redactor lets callers add secrets learned mid-session (a generated key).
func (l *SessionLog) Redactor() *Redactor { return l.red }

// Add records text, split into lines.
func (l *SessionLog) Add(text string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	for _, line := range strings.Split(strings.TrimRight(l.red.Redact(text), "\n"), "\n") {
		l.lines = append(l.lines, LogLine{Time: t, Text: line})
		if l.file != nil {
			fmt.Fprintf(l.file, "%s %s\n", t.Format("15:04:05"), line)
		}
	}
	if over := len(l.lines) - maxLogLines; over > 0 {
		l.lines = l.lines[over:]
	}
}

// Lines returns a copy of the log.
func (l *SessionLog) Lines() []LogLine {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]LogLine(nil), l.lines...)
}

// Close closes the log file, if any.
func (l *SessionLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// StepError says which step failed.
type StepError struct {
	Step   Step
	Result Result
	Err    error
}

func (e *StepError) Error() string {
	msg := fmt.Sprintf("step %q failed", e.Step.Title)
	switch {
	case e.Err != nil:
		msg += ": " + e.Err.Error()
	case e.Result.Exit != 0:
		msg += fmt.Sprintf(" (exit %d)", e.Result.Exit)
	}
	return msg
}

func (e *StepError) Unwrap() error { return e.Err }

const stepTimeout = 10 * time.Minute

// Execute runs the plan's steps in order on conn. It stops at the first
// failure, undoes the completed steps that can be undone (newest first),
// and returns a *StepError naming the step. progress, if set, is told about
// each step as it starts and finishes.
func Execute(ctx context.Context, conn Conn, p Plan, log *SessionLog, progress func(done, total int, title string)) error {
	if len(p.Blocked) > 0 {
		return fmt.Errorf("the plan is blocked: %s", strings.Join(p.Blocked, "; "))
	}
	var completed []Step
	for i, s := range p.Steps {
		if progress != nil {
			progress(i, len(p.Steps), s.Title)
		}
		log.Add(fmt.Sprintf("[%d/%d] %s", i+1, len(p.Steps), s.Title))
		log.Add("$ " + s.Cmd)
		res, err := runStep(ctx, conn, s)
		if out := strings.TrimSpace(res.Stdout + "\n" + res.Stderr); out != "" {
			log.Add(tailLines(out, 30))
		}
		failed := err != nil || res.Exit != 0 || (s.ID == "active" && strings.TrimSpace(res.Stdout) != "active")
		if failed {
			log.Add("✗ failed")
			for j := len(completed) - 1; j >= 0; j-- {
				if u := completed[j].Undo; u != "" {
					log.Add("↩ undoing: " + completed[j].Title)
					if r, uerr := runCmd(ctx, conn, u, nil); uerr != nil || r.Exit != 0 {
						log.Add("↩ the undo step also failed; check the server by hand")
					}
				}
			}
			return &StepError{Step: s, Result: res, Err: err}
		}
		completed = append(completed, s)
	}
	if progress != nil {
		progress(len(p.Steps), len(p.Steps), "done")
	}
	log.Add("✓ setup finished")
	return nil
}

func runStep(ctx context.Context, conn Conn, s Step) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	var stdin []byte
	if s.File != "" {
		stdin = s.Stdin
		if stdin == nil {
			stdin = []byte{}
		}
	}
	return runCmd(ctx, conn, s.Cmd, stdin)
}

func runCmd(ctx context.Context, conn Conn, cmd string, stdin []byte) (Result, error) {
	return conn.Run(ctx, "sh -c "+shq(cmd), stdin)
}

func tailLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = append([]string{fmt.Sprintf("… (%d earlier lines omitted)", len(lines)-n)}, lines[len(lines)-n:]...)
	}
	return strings.Join(lines, "\n")
}

// Outcome is what a finished setup learned.
type Outcome struct {
	Name     string `json:"name"`
	Link     string `json:"-"` // the share link: a secret
	EgressIP string `json:"egress_ip,omitempty"`
	DNSOK    bool   `json:"dns_ok"`
	Version  string `json:"version,omitempty"`
}

// Finish collects what the server can say for itself after setup: the
// version it runs, the public address its traffic leaves from, and whether
// it resolves names. (The client-side check, connecting through the node,
// is done by the caller once the node is imported.)
func Finish(ctx context.Context, conn Conn, p Plan, log *SessionLog) Outcome {
	o := Outcome{Name: p.Options.Name, Link: p.Link}
	if r, err := runCmd(ctx, conn, binPath+" version | head -1", nil); err == nil {
		o.Version = strings.TrimPrefix(strings.TrimSpace(r.Stdout), "sing-box version ")
	}
	if r, err := runCmd(ctx, conn, "curl -4 -fsS --max-time 8 https://api.ipify.org", nil); err == nil && r.OK() {
		o.EgressIP = strings.TrimSpace(r.Stdout)
	}
	if r, err := runCmd(ctx, conn, "getent hosts example.com", nil); err == nil && r.OK() && strings.TrimSpace(r.Stdout) != "" {
		o.DNSOK = true
	}
	log.Add(fmt.Sprintf("server reports: version %s, egress IP %s, DNS ok: %v", firstOr(o.Version, "unknown"), firstOr(o.EgressIP, "unknown"), o.DNSOK))
	return o
}

// ReadExisting recovers a previous install's settings and share link from
// the server, so repair, upgrade, and re-import work without new credentials.
func ReadExisting(ctx context.Context, conn Conn, host, name string) (port int, sni string, c Creds, link string, err error) {
	r, err := runCmd(ctx, conn, "cat "+shq(confPath), nil)
	if err != nil {
		return 0, "", Creds{}, "", err
	}
	if !r.OK() {
		return 0, "", Creds{}, "", errors.New("there is no Clash Mihomac config on the server")
	}
	port, sni, c, err = ParseServerConfig([]byte(r.Stdout))
	if err != nil {
		return 0, "", Creds{}, "", err
	}
	return port, sni, c, VlessRealityLink(name, host, port, c.UUID, c.PublicKey, c.ShortID, sni), nil
}

// InstallKey authorizes a public key for the login user, idempotently.
func InstallKey(ctx context.Context, conn Conn, authorizedKey string) error {
	if strings.ContainsAny(authorizedKey, "\n\r'") {
		return errors.New("invalid public key")
	}
	cmd := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && (grep -qxF %s ~/.ssh/authorized_keys || echo %s >> ~/.ssh/authorized_keys)", shq(authorizedKey), shq(authorizedKey))
	r, err := runCmd(ctx, conn, cmd, nil)
	if err != nil {
		return err
	}
	if !r.OK() {
		return fmt.Errorf("installing the key failed: %s", strings.TrimSpace(r.Stderr))
	}
	return nil
}

// DisablePasswordLogin turns off SSH password authentication. Call it only
// after a key login has been verified on a fresh connection. The change is
// validated with `sshd -t` before sshd is reloaded.
func DisablePasswordLogin(ctx context.Context, conn Conn) error {
	const path = "/etc/ssh/sshd_config.d/00-mihomac.conf"
	cmd := "[ -d /etc/ssh/sshd_config.d ] && grep -qi '^Include.*sshd_config.d' /etc/ssh/sshd_config && " +
		uploadCmd(path, "root:root", "0644", "022") +
		" && (sshd -t && (systemctl reload ssh 2>/dev/null || systemctl reload sshd)) || (rm -f " + shq(path) + "; echo 'could not apply' >&2; exit 1)"
	r, err := conn.Run(ctx, "sh -c "+shq(cmd), []byte("PasswordAuthentication no\nKbdInteractiveAuthentication no\n"))
	if err != nil {
		return err
	}
	if !r.OK() {
		return fmt.Errorf("couldn't turn off password login safely (nothing was changed): %s", strings.TrimSpace(r.Stderr))
	}
	return nil
}
