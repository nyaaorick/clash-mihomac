package verge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Runner runs a system command and returns its combined output. It
// matches netstate.Runner so the same fakes serve both.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// AppName is how macOS knows Clash Verge Rev.
const AppName = "Clash Verge"

// processName is the app's executable name as pgrep sees it.
const processName = "clash-verge"

// Running reports whether the Clash Verge app is running. This is the
// app itself, not its root service: the service stays up after the app
// quits, and mihomo goes with the app.
func Running(ctx context.Context, r Runner) bool {
	out, err := r.Run(ctx, "/usr/bin/pgrep", "-x", processName)
	return err == nil && strings.TrimSpace(out) != ""
}

// Restart quits Clash Verge and launches it again. Verge has no way to be
// told "re-read your profiles"; it rebuilds the config it gives mihomo on
// start, which is when a changed Merge file takes effect. Quitting
// through AppleScript lets Verge shut mihomo down cleanly and restore the
// system proxy and DNS; the app is relaunched once it is gone.
func Restart(ctx context.Context, r Runner) error {
	if Running(ctx, r) {
		if _, err := r.Run(ctx, "/usr/bin/osascript", "-e", fmt.Sprintf("tell application %q to quit", AppName)); err != nil {
			return fmt.Errorf("quit %s: %w", AppName, err)
		}
		// From here on the user has no proxy until Verge is back, so the
		// relaunch must happen even if the caller gives up (a closed
		// browser tab, a request timeout).
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 40*time.Second)
		defer cancel()
		if err := waitGone(ctx, r, 20*time.Second); err != nil {
			r.Run(ctx, "/usr/bin/open", "-a", AppName)
			return err
		}
	}
	if _, err := r.Run(ctx, "/usr/bin/open", "-a", AppName); err != nil {
		return fmt.Errorf("launch %s: %w", AppName, err)
	}
	return nil
}

func waitGone(ctx context.Context, r Runner, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for Running(ctx, r) {
		if time.Now().After(deadline) {
			return errors.New(AppName + " did not quit in time; quit it yourself and start it again")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return nil
}
