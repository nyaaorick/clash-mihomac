package helper

import (
	"net"
	"syscall"
)

// peerPID returns the PID of the process connected to a Unix socket.
func peerPID(conn net.Conn) int {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0
	}
	pid := 0
	raw.Control(func(fd uintptr) {
		const solLocal, localPeerPID = 0, 2 // <sys/un.h>
		pid, _ = syscall.GetsockoptInt(int(fd), solLocal, localPeerPID)
	})
	return pid
}
