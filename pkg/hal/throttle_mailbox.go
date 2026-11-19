//go:build !tinygo

package hal

import "fmt"

const (
	// mboxTagGetThrottled is the firmware property tag behind `vcgencmd get_throttled`
	mboxTagGetThrottled = 0x00030046
	// mboxResponseSuccess marks a property message the firmware processed successfully
	mboxResponseSuccess = 0x80000000
	// mboxTagResponse marks a tag the firmware answered; the lower bits are the length of the response value
	mboxTagResponse = 0x80000000
)

// throttledMessage is a firmware property message carrying a single get_throttled tag
type throttledMessage [7]uint32

// newThrottledRequest builds the property message asking for the throttle status. The request value is the mask of
// sticky "occurred" bits to clear: 0 leaves them alone.
func newThrottledRequest() throttledMessage {
	return throttledMessage{
		7 * 4,               // message size in bytes
		0,                   // request
		mboxTagGetThrottled, // tag
		4,                   // value buffer size
		0,                   // tag request
		0,                   // value: don't clear sticky bits
		0,                   // end tag
	}
}

// parseThrottledResponse extracts the throttle status from the firmware's answer to newThrottledRequest.
func parseThrottledResponse(msg throttledMessage) (ThrottleStatus, error) {
	if msg[1] != mboxResponseSuccess {
		return 0, fmt.Errorf("firmware didn't process the property request (code 0x%08x)", msg[1])
	}
	if msg[4]&mboxTagResponse == 0 || msg[4]&^mboxTagResponse < 4 {
		return 0, fmt.Errorf("firmware didn't answer the get_throttled tag (0x%08x)", msg[4])
	}
	return ThrottleStatus(msg[5]), nil
}
