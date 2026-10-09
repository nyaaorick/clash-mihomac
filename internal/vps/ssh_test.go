package vps

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startSSHServer runs a tiny in-process SSH server. It "executes" commands
// itself: `echo X` prints X, `exit N` exits with N, `cat` echoes stdin.
func startSSHServer(t *testing.T, password string, authorized ssh.PublicKey) (addr string, fingerprint string) {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if password != "" && string(pw) == password {
				return nil, nil
			}
			return nil, errors.New("bad password")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if authorized != nil && string(key.Marshal()) == string(authorized.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range creqs {
							if req.Type != "exec" {
								req.Reply(false, nil)
								continue
							}
							req.Reply(true, nil)
							cmd := string(req.Payload[4:])
							status := byte(0)
							switch {
							case cmd == "cat":
								io.Copy(ch, ch)
							case strings.HasPrefix(cmd, "echo "):
								io.WriteString(ch, strings.TrimPrefix(cmd, "echo ")+"\n")
							case strings.HasPrefix(cmd, "exit "):
								status = cmd[len("exit ")] - '0'
								io.WriteString(ch.Stderr(), "failing\n")
							}
							ch.SendRequest("exit-status", false, []byte{0, 0, 0, status})
							ch.Close()
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), ssh.FingerprintSHA256(hostSigner.PublicKey())
}

func target(addr string) Target {
	host, port, _ := net.SplitHostPort(addr)
	var p int
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	return Target{Host: host, Port: p, User: "root"}
}

func TestSSHDialerPasswordAndHostKeyPinning(t *testing.T) {
	addr, fp := startSSHServer(t, "hunter2", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := SSHDialer{Timeout: 5 * time.Second}

	tg := target(addr)
	tg.Password = "hunter2"
	conn, err := d.Dial(ctx, tg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.HostKey() != fp {
		t.Errorf("host key %q, want %q", conn.HostKey(), fp)
	}
	if r, err := conn.Run(ctx, "echo hello", nil); err != nil || r.Stdout != "hello\n" || r.Exit != 0 {
		t.Errorf("echo = %+v, %v", r, err)
	}
	if r, err := conn.Run(ctx, "exit 3", nil); err != nil || r.Exit != 3 || r.Stderr != "failing\n" || r.OK() {
		t.Errorf("exit = %+v, %v", r, err)
	}
	if r, err := conn.Run(ctx, "cat", []byte("piped in")); err != nil || r.Stdout != "piped in" {
		t.Errorf("cat = %+v, %v", r, err)
	}

	// Pinned fingerprint: right one works, wrong one is refused.
	tg.HostKey = fp
	if c, err := d.Dial(ctx, tg); err != nil {
		t.Errorf("pinned dial: %v", err)
	} else {
		c.Close()
	}
	tg.HostKey = "SHA256:somethingelse"
	_, err = d.Dial(ctx, tg)
	var hk *HostKeyError
	if !errors.As(err, &hk) || hk.Got != fp {
		t.Errorf("wrong pin err = %v", err)
	}

	tg.HostKey, tg.Password = "", "wrong"
	if _, err := d.Dial(ctx, tg); err == nil {
		t.Error("wrong password accepted")
	}
	if _, err := d.Dial(ctx, Target{Host: "127.0.0.1", Port: 1}); err == nil || !strings.Contains(err.Error(), "no password or key") {
		t.Errorf("no credentials: %v", err)
	}
}

func TestSSHDialerKeyLogin(t *testing.T) {
	priv, pubLine, err := GenerateKey("mihomac-test")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubLine))
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := startSSHServer(t, "", pub)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tg := target(addr)
	tg.KeyPEM = priv
	conn, err := SSHDialer{}.Dial(ctx, tg)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	other, _, _ := GenerateKey("other")
	tg.KeyPEM = other
	if _, err := (SSHDialer{}).Dial(ctx, tg); err == nil {
		t.Error("unknown key accepted")
	}
	tg.KeyPEM = []byte("garbage")
	if _, err := (SSHDialer{}).Dial(ctx, tg); err == nil {
		t.Error("garbage key accepted")
	}
	if !strings.HasPrefix(pubLine, "ssh-ed25519 ") || !strings.HasSuffix(pubLine, " mihomac-test") {
		t.Errorf("authorized key line = %q", pubLine)
	}
}
