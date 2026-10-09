package vps

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Target is a server to connect to. A password is held in memory for the
// length of a setup only; it is never written to disk.
type Target struct {
	Host     string
	Port     int
	User     string
	Password string
	KeyPEM   []byte // private key, for key login
	// HostKey is the SHA256 fingerprint the server must present. Empty
	// means "trust on first use": the fingerprint is reported by
	// Conn.HostKey so it can be shown and pinned.
	HostKey string
}

// Result is the outcome of a remote command.
type Result struct {
	Stdout string
	Stderr string
	Exit   int
}

// OK reports whether the command exited with status 0.
func (r Result) OK() bool { return r.Exit == 0 }

// Conn is an open SSH connection.
type Conn interface {
	// Run runs a shell command, feeding stdin to it when non-nil. A command
	// that runs and fails is not an error: check Result.Exit.
	Run(ctx context.Context, cmd string, stdin []byte) (Result, error)
	// HostKey is the server's SHA256 host-key fingerprint.
	HostKey() string
	Close() error
}

// Dialer opens connections.
type Dialer interface {
	Dial(ctx context.Context, t Target) (Conn, error)
}

// HostKeyError is returned when a server's key differs from the pinned one.
type HostKeyError struct{ Want, Got string }

func (e *HostKeyError) Error() string {
	return fmt.Sprintf("the server's SSH host key changed (expected %s, got %s): either the server was reinstalled or someone is intercepting the connection; refusing to continue", e.Want, e.Got)
}

// maxOutput caps captured command output.
const maxOutput = 4 << 20

// SSHDialer is the real Dialer, built on golang.org/x/crypto/ssh.
type SSHDialer struct {
	Timeout time.Duration // connection timeout; default 15s
}

type sshConn struct {
	client  *ssh.Client
	hostKey string
}

// Dial implements Dialer.
func (d SSHDialer) Dial(ctx context.Context, t Target) (Conn, error) {
	if t.Port == 0 {
		t.Port = 22
	}
	if t.User == "" {
		t.User = "root"
	}
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	var methods []ssh.AuthMethod
	if len(t.KeyPEM) > 0 {
		signer, err := ssh.ParsePrivateKey(t.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("read SSH key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if t.Password != "" {
		methods = append(methods, ssh.Password(t.Password))
	}
	if len(methods) == 0 {
		return nil, errors.New("no password or key given")
	}
	c := &sshConn{}
	cfg := &ssh.ClientConfig{
		User: t.User, Auth: methods, Timeout: timeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			c.hostKey = ssh.FingerprintSHA256(key)
			if t.HostKey != "" && t.HostKey != c.hostKey {
				return &HostKeyError{Want: t.HostKey, Got: c.hostKey}
			}
			return nil
		},
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	nd := net.Dialer{Timeout: timeout}
	raw, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	sc, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		raw.Close()
		var hk *HostKeyError
		if errors.As(err, &hk) {
			return nil, hk
		}
		return nil, fmt.Errorf("SSH login to %s as %s: %w", addr, t.User, err)
	}
	c.client = ssh.NewClient(sc, chans, reqs)
	return c, nil
}

func (c *sshConn) HostKey() string { return c.hostKey }
func (c *sshConn) Close() error    { return c.client.Close() }

func (c *sshConn) Run(ctx context.Context, cmd string, stdin []byte) (Result, error) {
	sess, err := c.client.NewSession()
	if err != nil {
		return Result{}, err
	}
	defer sess.Close()
	var out, errb limitedBuffer
	sess.Stdout, sess.Stderr = &out, &errb
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		sess.Close()
		return Result{}, ctx.Err()
	case err := <-done:
		res := Result{Stdout: out.String(), Stderr: errb.String()}
		var exit *ssh.ExitError
		switch {
		case err == nil:
		case errors.As(err, &exit):
			res.Exit = exit.ExitStatus()
		default:
			return res, err
		}
		return res, nil
	}
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxOutput {
		p = p[:max(0, maxOutput-b.Len())]
	}
	b.Buffer.Write(p)
	return len(p), nil // keep draining so the remote command isn't blocked
}

// GenerateKey makes an ed25519 key pair for key login. It returns the
// private key in OpenSSH PEM form and the public key as an authorized_keys line.
func GenerateKey(comment string) (privatePEM []byte, authorizedKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		line += " " + comment
	}
	return pem.EncodeToMemory(block), line, nil
}
