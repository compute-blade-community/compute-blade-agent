//go:build !linux

package discovery

import "context"

// advertiseAvahi is only supported on Linux
func advertiseAvahi(context.Context, Advertisement) error {
	return errAvahiUnavailable
}
