package ledengine_test

import (
	"context"
	"testing"

	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/compute-blade-community/compute-blade-agent/pkg/ledengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingEngine is a LedEngine that records every pattern it is asked to show
type recordingEngine struct {
	patterns []ledengine.BlinkPattern
}

func (r *recordingEngine) SetPattern(p ledengine.BlinkPattern) error {
	r.patterns = append(r.patterns, p)
	return nil
}

func (r *recordingEngine) Run(context.Context) error { return nil }

func (r *recordingEngine) last() ledengine.BlinkPattern {
	return r.patterns[len(r.patterns)-1]
}

var (
	colorIdle     = led.Color{Green: 16}
	colorIdentify = led.Color{Red: 16, Blue: 16}
	colorStall    = led.Color{Red: 64, Green: 24}
)

func TestStack_ShowsHighestPriorityActiveLayer(t *testing.T) {
	t.Parallel()

	engine := &recordingEngine{}
	base := ledengine.NewStaticPattern(colorIdle)
	identify := ledengine.NewBurstPattern(led.Color{}, colorIdentify)
	stall := ledengine.NewFastBlinkPattern(led.Color{}, colorStall)

	stack, err := ledengine.NewStack(engine, base)
	require.NoError(t, err)
	assert.Equal(t, base, engine.last())

	require.NoError(t, stack.Define("identify", 1000, identify))
	require.NoError(t, stack.Define("fan_stall", 30, stall))
	assert.Equal(t, "", stack.Shown())

	require.NoError(t, stack.Activate("fan_stall"))
	assert.Equal(t, "fan_stall", stack.Shown())
	assert.Equal(t, stall, engine.last())

	// identify outranks the stall indicator...
	require.NoError(t, stack.Activate("identify"))
	assert.Equal(t, "identify", stack.Shown())
	assert.Equal(t, identify, engine.last())

	// ...and the stall indicator comes back once identify is confirmed
	require.NoError(t, stack.Deactivate("identify"))
	assert.Equal(t, "fan_stall", stack.Shown())
	assert.Equal(t, stall, engine.last())

	require.NoError(t, stack.Deactivate("fan_stall"))
	assert.Equal(t, "", stack.Shown())
	assert.Equal(t, base, engine.last())
}

func TestStack_DoesNotRestartUnchangedPattern(t *testing.T) {
	t.Parallel()

	engine := &recordingEngine{}
	stack, err := ledengine.NewStack(engine, ledengine.NewStaticPattern(colorIdle))
	require.NoError(t, err)
	require.NoError(t, stack.Define("identify", 1000, ledengine.NewBurstPattern(led.Color{}, colorIdentify)))
	require.NoError(t, stack.Define("fan_stall", 30, ledengine.NewFastBlinkPattern(led.Color{}, colorStall)))

	require.NoError(t, stack.Activate("identify"))
	calls := len(engine.patterns)

	// activating twice, or activating a lower layer underneath, must not restart the blinking identify pattern
	require.NoError(t, stack.Activate("identify"))
	require.NoError(t, stack.Activate("fan_stall"))
	assert.Equal(t, calls, len(engine.patterns))
}

func TestStack_UnknownLayer(t *testing.T) {
	t.Parallel()

	stack, err := ledengine.NewStack(&recordingEngine{}, ledengine.NewStaticPattern(colorIdle))
	require.NoError(t, err)
	assert.Error(t, stack.Activate("nope"))
	assert.False(t, stack.Defined("nope"))
}

func TestStack_SetBase(t *testing.T) {
	t.Parallel()

	engine := &recordingEngine{}
	stack, err := ledengine.NewStack(engine, ledengine.NewStaticPattern(colorIdle))
	require.NoError(t, err)

	off := ledengine.NewStaticPattern(led.Color{})
	require.NoError(t, stack.SetBase(off))
	assert.Equal(t, off, engine.last())
}

func TestPatternFromName(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"static", "slow-blink", "fast-blink", "burst"} {
		p, err := ledengine.PatternFromName(name, colorStall)
		require.NoError(t, err, name)
		assert.NotEmpty(t, p.Delays, name)
		assert.Equal(t, colorStall, p.ActiveColor, name)
	}

	_, err := ledengine.PatternFromName("disco", colorStall)
	assert.Error(t, err)
}
