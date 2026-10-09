// Command mihomac-helper is Clash Mihomac's privileged helper.
//
// It is installed as a launchd daemon running as root. It runs TUN cores,
// sets the system proxy, keeps a backup of the network settings it
// changes, and restores them when a client exits, a core dies, the helper
// stops, or (via its startup self-check) after a crash or reboot. Clients
// reach it over a Unix socket that only one user can open. See
// internal/helper for the protocol.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nyaaorick/clash-mihomac/internal/buildinfo"
	"github.com/nyaaorick/clash-mihomac/internal/helper"
)

func main() {
	socket := flag.String("socket", helper.DefaultSocket, "Unix socket to listen on")
	root := flag.String("root", helper.DefaultRoot, "directory for the network backup and TUN cores")
	uid := flag.Int("allow-uid", -1, "the only non-root user allowed to connect (required)")
	flag.Parse()

	if err := run(*socket, *root, *uid); err != nil {
		log.Fatal(err)
	}
}

func run(socket, root string, uid int) error {
	if uid < 0 {
		return fmt.Errorf("--allow-uid is required")
	}
	isRoot := os.Geteuid() == 0
	if !isRoot {
		log.Printf("warning: not running as root; TUN and network changes will fail (development only)")
		if uid != os.Getuid() {
			return fmt.Errorf("--allow-uid %d must be your own uid (%d) when not running as root", uid, os.Getuid())
		}
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}

	// Only replace a stale socket, never some other file at that path.
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s exists and is not a socket", socket)
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
	}
	old := syscall.Umask(0o177) // socket is created 0600
	ln, err := net.Listen("unix", socket)
	syscall.Umask(old)
	if err != nil {
		return err
	}
	defer os.Remove(socket)
	if isRoot {
		if err := os.Chown(socket, uid, -1); err != nil {
			return err
		}
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)
	svc := helper.NewService(root, uid, buildinfo.Version, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	svc.Recover(ctx)
	go svc.Watch(ctx)
	logger.Printf("mihomac-helper %s listening on %s (uid %d, root %s)", buildinfo.Version, socket, uid, root)
	err = helper.Serve(ctx, ln, svc.Commands())

	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	svc.Shutdown(sctx)
	logger.Printf("stopped; all sessions ended")
	return err
}
