//go:build !tinygo

package hal

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestButtonDebouncer_BouncesYieldOneTransition(t *testing.T) {
	t.Parallel()

	var level atomic.Bool
	var mu sync.Mutex
	var transitions []bool

	d := &buttonDebouncer{
		settle: 10 * time.Millisecond,
		read:   func() (bool, error) { return level.Load(), nil },
		emit: func(pressed bool, _ time.Time) {
			mu.Lock()
			defer mu.Unlock()
			transitions = append(transitions, pressed)
		},
	}
	defer d.stop()

	got := func() []bool {
		mu.Lock()
		defer mu.Unlock()
		return append([]bool(nil), transitions...)
	}

	// press with contact bounce
	level.Store(true)
	for i := 0; i < 5; i++ {
		d.edge()
		time.Sleep(time.Millisecond)
	}
	assert.Eventually(t, func() bool { return len(got()) == 1 }, time.Second, time.Millisecond)

	// bounce settles on the same level: no new transition
	d.edge()
	time.Sleep(30 * time.Millisecond)
	assert.Equal(t, []bool{true}, got())

	// release
	level.Store(false)
	d.edge()
	d.edge()
	assert.Eventually(t, func() bool { return len(got()) == 2 }, time.Second, time.Millisecond)
	assert.Equal(t, []bool{true, false}, got())
}

func TestSendButtonEvent_DropsWhenFull(t *testing.T) {
	t.Parallel()

	ch := make(chan ButtonEvent, 1)
	sendButtonEvent(ch, ButtonEvent{Pressed: true})
	sendButtonEvent(ch, ButtonEvent{Pressed: false}) // must not block
	assert.Len(t, ch, 1)
}
