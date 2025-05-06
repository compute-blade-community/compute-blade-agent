package ledengine

import (
	"github.com/uptime-industries/compute-blade-agent/pkg/hal"
	"github.com/uptime-industries/compute-blade-agent/pkg/util"
)

// Options are the options for the LedEngine
type Options struct {
	// LedIdx is the index of the LED to control
	LedIdx uint
	// Hal is the computeblade hardware abstraction layer
	Hal hal.ComputeBladeHal
	// Clock is the clock used for timing
	Clock util.Clock
}
