//go:build !linux && !tinygo

package hal

func readMailboxThrottled(string) (ThrottleStatus, error) {
	return 0, ErrNotSupported
}
