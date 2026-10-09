package helper

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/netstate/netstatetest"
)

// startHelper serves a test Service on a temporary socket. The path is
// kept short because macOS limits Unix socket paths to 104 bytes.
func startHelper(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{Root: dir, UID: -1, Version: "test", Log: log.New(io.Discard, "", 0), Runner: netstatetest.New()}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Serve(ctx, ln, s.Commands())
	return sock
}

func callSock(t *testing.T, sock, cmd string, args, out any) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return Call(ctx, sock, cmd, args, out)
}

func TestPingOverSocket(t *testing.T) {
	sock := startHelper(t)
	var res map[string]string
	if err := callSock(t, sock, "ping", nil, &res); err != nil || res["version"] != "test" {
		t.Errorf("ping = %v, %v", res, err)
	}
}

func TestPeerPIDIsCaller(t *testing.T) {
	sock := startHelper(t)
	var res StatusResult
	if err := callSock(t, sock, "sysproxy-set", InstanceArgs{Instance: "debug"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := callSock(t, sock, "status", nil, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Sessions) != 1 || res.Sessions[0].ClientPID != os.Getpid() {
		t.Errorf("session client pid = %+v, want %d", res.Sessions, os.Getpid())
	}
}

func TestUnknownCommandRejected(t *testing.T) {
	sock := startHelper(t)
	if err := callSock(t, sock, "rm -rf /", nil, nil); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("err = %v, want unknown command", err)
	}
}

func TestMalformedAndOversizedRequests(t *testing.T) {
	cmds := (&Service{}).Commands()
	for name, body := range map[string]string{
		"not json":      "hello",
		"unknown field": `{"cmd":"ping","extra":["x"]}`,
		"oversized":     `{"cmd":"` + strings.Repeat("a", maxRequest) + `"}`,
	} {
		if resp := dispatch(context.Background(), strings.NewReader(body), Peer{}, cmds); resp.OK {
			t.Errorf("%s: accepted", name)
		}
	}
	resp := dispatch(context.Background(), strings.NewReader(`{"cmd":"tun-stop","args":{"instance":"debug","rogue":1}}`), Peer{}, cmds)
	if resp.OK {
		t.Error("unknown argument field accepted")
	}
}
