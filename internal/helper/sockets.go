package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"os/user"
	"strconv"
	"strings"

	"github.com/nyaaorick/clash-mihomac/internal/traffic"
)

// lsofArgs is the one fixed lsof invocation the helper will run. Run as
// root it sees every process's sockets, which an unprivileged lsof can't.
var lsofArgs = []string{"-nP", "-w", "+c", "0", "-i", "-U", "-F", "pcLftPnT"}

const (
	lsofBin        = "/usr/sbin/lsof"
	maxLsofOutput  = 32 << 20
	maxSocketsSent = 20000
)

// SocketsResult is the sockets command's reply.
type SocketsResult struct {
	Sockets   []traffic.Socket `json:"sockets"`
	Truncated bool             `json:"truncated,omitempty"`
}

// sockets reports the machine's socket table. It takes no arguments and is
// read-only. Other people's processes are left out: the table is for the
// one user the helper serves, plus root and system accounts, which are
// what a root-only view adds.
func (s *Service) sockets(ctx context.Context, _ Peer, raw json.RawMessage) (any, error) {
	var none struct{}
	if err := decodeArgs(raw, &none); err != nil {
		return nil, err
	}
	out, err := s.Runner.Run(ctx, lsofBin, lsofArgs...)
	if err != nil && out == "" {
		return nil, fmt.Errorf("lsof: %w", err)
	}
	if len(out) > maxLsofOutput {
		return nil, fmt.Errorf("lsof output is larger than %d bytes", maxLsofOutput)
	}
	all, err := traffic.ParseLsof(out)
	if err != nil {
		return nil, err
	}
	allowed := s.allowedUsers()
	res := SocketsResult{Sockets: make([]traffic.Socket, 0, len(all))}
	for _, sk := range all {
		if !allowed(sk.User) {
			continue
		}
		if len(res.Sockets) == maxSocketsSent {
			res.Truncated = true
			break
		}
		res.Sockets = append(res.Sockets, sk)
	}
	return res, nil
}

// allowedUsers returns whose sockets the caller may see.
func (s *Service) allowedUsers() func(string) bool {
	name := ""
	if s.UID >= 0 {
		if u, err := user.LookupId(strconv.Itoa(s.UID)); err == nil {
			name = u.Username
		}
	}
	return func(owner string) bool {
		switch {
		case owner == "root", strings.HasPrefix(owner, "_"):
			return true
		case s.UID < 0:
			return true // tests run with no particular user
		}
		return name != "" && owner == name
	}
}
