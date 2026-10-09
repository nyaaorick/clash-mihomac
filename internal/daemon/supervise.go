package daemon

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// Supervise runs the core as a child and stops it as soon as its own stdin
// reaches EOF. The daemon holds the other end of that pipe, and the kernel
// closes it however the daemon dies (even kill -9), so a user-mode core
// never outlives its daemon. It also forwards SIGTERM and SIGINT.
func Supervise(core string, args []string) error {
	cmd := exec.Command(core, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	eof := make(chan struct{})
	go func() {
		io.Copy(io.Discard, os.Stdin)
		close(eof)
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

	select {
	case err := <-done:
		return err
	case <-eof:
	case <-sig:
	}
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		<-done
	}
	return nil
}
