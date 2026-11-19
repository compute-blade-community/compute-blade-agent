package hal

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The power_status metric labels its series with fmt.Sprint of the power status; they must be the documented names.
func TestPowerStatus_MetricLabel(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "poe+", fmt.Sprint(PowerPoe802at))
	assert.Equal(t, "poeOrUsbC", fmt.Sprint(PowerPoeOrUsbC))
	assert.Equal(t, "undefined", fmt.Sprint(PowerStatus(42)))
}
