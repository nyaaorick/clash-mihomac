// Package helper implements Clash Mihomac's privileged helper and the
// protocol clients use to talk to it.
//
// The helper runs as root under launchd and listens on a Unix socket owned
// by the one user allowed to use it (mode 0600). Each connection carries a
// single JSON request naming a command from a fixed allowlist. The caller's
// PID is taken from the socket itself (LOCAL_PEERPID), never from the
// request, and becomes the session's dead-man switch: when that process
// exits, the helper tears the session down and restores the network.
package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

// DefaultSocket is where the installed helper listens.
const DefaultSocket = "/var/run/com.clashmihomac.helper.sock"

// maxRequest bounds a request; configs with many proxies can be large.
const maxRequest = 8 << 20

// Request is one call to the helper.
type Request struct {
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args,omitempty"`
}

// Response is the helper's reply.
type Response struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Peer identifies the process on the other end of a connection, and holds
// any open files it passed along with the request.
type Peer struct {
	PID   int
	Files []*os.File
}

// Every request starts with one header byte. When it is hasFiles, the
// same message carries open file descriptors (SCM_RIGHTS). Passing a file
// this way lets the helper read something the client opened without ever
// opening a user-supplied path as root (and works under macOS privacy
// protection, which blocks root daemons from ~/Desktop and similar).
const (
	noFiles  = 0
	hasFiles = 1
	maxFiles = 4
)

// Command handles one allowlisted request.
type Command func(ctx context.Context, peer Peer, args json.RawMessage) (any, error)

// Serve answers requests on ln until ctx is cancelled.
func Serve(ctx context.Context, ln net.Listener, cmds map[string]Command) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handle(ctx, conn, cmds)
	}
}

func handle(ctx context.Context, conn net.Conn, cmds map[string]Command) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Minute))
	peer := Peer{PID: peerPID(conn)}
	files, err := readHeader(conn)
	peer.Files = files
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	resp := Response{Error: "bad request"}
	if err == nil {
		resp = dispatch(ctx, conn, peer, cmds)
	}
	json.NewEncoder(conn).Encode(resp)
}

// readHeader reads the request's header byte and any passed files.
func readHeader(conn net.Conn) ([]*os.File, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("not a unix socket")
	}
	buf := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(maxFiles*4))
	n, oobn, _, _, err := uc.ReadMsgUnix(buf, oob)
	if err != nil || n != 1 {
		return nil, fmt.Errorf("read header: %v", err)
	}
	var files []*os.File
	if oobn > 0 {
		msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			fds, err := syscall.ParseUnixRights(&m)
			if err != nil {
				continue
			}
			for _, fd := range fds {
				files = append(files, os.NewFile(uintptr(fd), "passed-file"))
			}
		}
	}
	if (buf[0] == hasFiles) != (len(files) > 0) || buf[0] > hasFiles {
		for _, f := range files {
			f.Close()
		}
		return nil, errors.New("bad header")
	}
	return files, nil
}

func dispatch(ctx context.Context, r io.Reader, peer Peer, cmds map[string]Command) Response {
	var req Request
	dec := json.NewDecoder(io.LimitReader(r, maxRequest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return Response{Error: "bad request"}
	}
	cmd, ok := cmds[req.Cmd]
	if !ok {
		return Response{Error: fmt.Sprintf("unknown command %q", req.Cmd)}
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	result, err := cmd(cctx, peer, req.Args)
	if err != nil {
		return Response{Error: err.Error()}
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, Result: raw}
}

// decodeArgs strictly decodes a command's arguments.
func decodeArgs(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("bad arguments: %w", err)
	}
	return nil
}

// Call sends one command to the helper listening on socket, passing any
// files along. If result is non-nil the reply is decoded into it.
func Call(ctx context.Context, socket, cmd string, args, result any, files ...*os.File) error {
	if len(files) > maxFiles {
		return fmt.Errorf("at most %d files per call", maxFiles)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("connect to helper at %s: %w (is it installed? see `make install-helper`)", socket, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	header, oob := []byte{noFiles}, []byte(nil)
	if len(files) > 0 {
		fds := make([]int, len(files))
		for i, f := range files {
			fds[i] = int(f.Fd())
		}
		header[0], oob = hasFiles, syscall.UnixRights(fds...)
	}
	if _, _, err := conn.(*net.UnixConn).WriteMsgUnix(header, oob, nil); err != nil {
		return err
	}
	req := Request{Cmd: cmd}
	if args != nil {
		if req.Args, err = json.Marshal(args); err != nil {
			return err
		}
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("read helper response: %w", err)
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	if result != nil {
		return json.Unmarshal(resp.Result, result)
	}
	return nil
}
