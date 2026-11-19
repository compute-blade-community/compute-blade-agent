package button_test

import (
	"testing"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/button"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var t0 = time.Unix(1000, 0)

func ms(n int) time.Time { return t0.Add(time.Duration(n) * time.Millisecond) }

func newRecognizer() *button.Recognizer {
	return button.NewRecognizer(button.Config{
		Window:       400 * time.Millisecond,
		FireAt:       5,
		LongPress:    5 * time.Second,
		HoldFeedback: time.Second,
	})
}

// click presses at start and releases 100ms later
func click(r *button.Recognizer, start int) []button.Gesture {
	return append(r.Press(ms(start)), r.Release(ms(start+100))...)
}

func TestRecognizer_SinglePress(t *testing.T) {
	t.Parallel()

	r := newRecognizer()
	assert.Empty(t, click(r, 0))

	deadline, ok := r.NextDeadline(ms(100))
	require.True(t, ok)
	assert.Empty(t, r.Tick(ms(400)), "window not over yet")
	assert.Equal(t, []button.Gesture{{Presses: 1}}, r.Tick(deadline))

	_, ok = r.NextDeadline(deadline)
	assert.False(t, ok, "idle again")
}

func TestRecognizer_DoublePress(t *testing.T) {
	t.Parallel()

	r := newRecognizer()
	assert.Empty(t, click(r, 0))
	assert.Empty(t, click(r, 300)) // 200ms after the first release
	assert.Equal(t, []button.Gesture{{Presses: 2}}, r.Tick(ms(900)))
}

func TestRecognizer_PressesTooFarApartAreSeparateSeries(t *testing.T) {
	t.Parallel()

	r := newRecognizer()
	assert.Empty(t, click(r, 0))
	assert.Equal(t, []button.Gesture{{Presses: 1}}, r.Tick(ms(600)))
	assert.Empty(t, click(r, 700))
	assert.Equal(t, []button.Gesture{{Presses: 1}}, r.Tick(ms(1300)))
}

func TestRecognizer_LateTickIsCaughtUpOnPress(t *testing.T) {
	t.Parallel()

	r := newRecognizer()
	assert.Empty(t, click(r, 0))
	// no Tick happened; the next press comes long after the window
	assert.Equal(t, []button.Gesture{{Presses: 1}}, r.Press(ms(2000)))
	assert.Empty(t, r.Release(ms(2100)))
	assert.Equal(t, []button.Gesture{{Presses: 1}}, r.Tick(ms(2600)))
}

func TestRecognizer_FireAtEndsSeriesImmediately(t *testing.T) {
	t.Parallel()

	r := newRecognizer()
	for i := 0; i < 4; i++ {
		assert.Empty(t, click(r, i*250))
	}
	// the 5th release fires without waiting for the window
	assert.Empty(t, r.Press(ms(1000)))
	assert.Equal(t, []button.Gesture{{Presses: 5}}, r.Release(ms(1100)))

	_, ok := r.NextDeadline(ms(1100))
	assert.False(t, ok)
}

func TestRecognizer_LongPress(t *testing.T) {
	t.Parallel()

	r := newRecognizer()
	assert.Empty(t, r.Press(ms(0)))

	// first wake-up at the feedback threshold
	deadline, ok := r.NextDeadline(ms(0))
	require.True(t, ok)
	assert.Equal(t, ms(1000), deadline)
	assert.False(t, r.Holding(ms(999)))
	assert.Empty(t, r.Tick(deadline))
	assert.True(t, r.Holding(deadline))

	// then at the long press threshold
	deadline, ok = r.NextDeadline(ms(1000))
	require.True(t, ok)
	assert.Equal(t, ms(5000), deadline)
	assert.Equal(t, []button.Gesture{{Long: true, Held: 5 * time.Second}}, r.Tick(deadline))
	assert.False(t, r.Holding(ms(5001)), "no feedback once the long press fired")

	// the release is consumed
	assert.Empty(t, r.Release(ms(6000)))
	_, ok = r.NextDeadline(ms(6000))
	assert.False(t, ok)
}

func TestRecognizer_LongPressDetectedOnReleaseWithoutTick(t *testing.T) {
	t.Parallel()

	r := newRecognizer()
	assert.Empty(t, r.Press(ms(0)))
	assert.Equal(t, []button.Gesture{{Long: true, Held: 6 * time.Second}}, r.Release(ms(6000)))
}

func TestRecognizer_LongPressDiscardsSeries(t *testing.T) {
	t.Parallel()

	r := newRecognizer()
	assert.Empty(t, click(r, 0))
	assert.Empty(t, r.Press(ms(300)))
	assert.Equal(t, []button.Gesture{{Long: true, Held: 5 * time.Second}}, r.Tick(ms(5300)))
	assert.Empty(t, r.Release(ms(5400)))
	assert.Empty(t, r.Tick(ms(6000)))
}

func TestRecognizer_LongPressDisabled(t *testing.T) {
	t.Parallel()

	r := button.NewRecognizer(button.Config{Window: 400 * time.Millisecond})
	assert.Empty(t, r.Press(ms(0)))
	_, ok := r.NextDeadline(ms(0))
	assert.False(t, ok)
	assert.False(t, r.Holding(ms(10000)))

	// a very long press is just a press
	assert.Empty(t, r.Release(ms(10000)))
	assert.Equal(t, []button.Gesture{{Presses: 1}}, r.Tick(ms(10500)))
}

func TestRecognizer_IgnoresDuplicateTransitions(t *testing.T) {
	t.Parallel()

	r := newRecognizer()
	assert.Empty(t, r.Release(ms(0)), "release without press")
	assert.Empty(t, r.Press(ms(10)))
	assert.Empty(t, r.Press(ms(20)), "press while pressed")
	assert.Empty(t, r.Release(ms(100)))
	assert.Equal(t, []button.Gesture{{Presses: 1}}, r.Tick(ms(600)))
}
