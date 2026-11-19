//go:build linux && !tinygo

package hal

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// mboxPropertyIoctl is IOCTL_MBOX_PROPERTY of the vcio driver: _IOWR(100, 0, char *)
const mboxPropertyIoctl = 3<<30 | uintptr(unsafe.Sizeof(uintptr(0)))<<16 | 100<<8

// readMailboxThrottled asks the VideoCore firmware for the throttle status through the vcio mailbox device, like
// `vcgencmd get_throttled` does.
func readMailboxThrottled(path string) (ThrottleStatus, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()

	msg := newThrottledRequest()
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), mboxPropertyIoctl, uintptr(unsafe.Pointer(&msg[0]))); errno != 0 {
		return 0, errno
	}
	return parseThrottledResponse(msg)
}
