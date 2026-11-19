package internal_agent

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/actions"
	"github.com/compute-blade-community/compute-blade-agent/pkg/agent"
	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func defaultButtonConfig() agent.ButtonConfig {
	return agent.ButtonConfig{
		GestureWindow: 100 * time.Millisecond,
		LongPress:     agent.LongPressConfig{Hold: 2 * time.Second},
		MultiPress:    agent.MultiPressConfig{Count: 5},
	}
}

// newButtonTestAgent creates an agent with fake built-in actions that count their invocations
func newButtonTestAgent(t *testing.T, cfg agent.ButtonConfig) (*computeBladeAgent, map[string]*atomic.Int32) {
	t.Helper()

	a, err := newLedTestAgent(t, nil)
	require.NoError(t, err)
	a.config.Button = cfg
	a.hostname = "blade-test"

	calls := map[string]*atomic.Int32{}
	builtins := map[string]actions.Builtin{}
	for _, name := range []string{actionNone, actionIdentifyToggle, actionShutdown, actionReboot, actionEmergencyPoweroff} {
		counter := &atomic.Int32{}
		calls[name] = counter
		builtins[name] = func(context.Context) error { counter.Add(1); return nil }
	}
	a.actions = actions.NewRunner(builtins)

	return a, calls
}

func TestSetupButtons_DefaultsSingleToIdentify(t *testing.T) {
	t.Parallel()

	a, _ := newButtonTestAgent(t, defaultButtonConfig())
	require.NoError(t, a.setupButtons())

	assert.Equal(t, actionIdentifyToggle, a.buttons.cfg.Single.Action)
	assert.False(t, a.buttons.holdFeedback, "no long press action bound")
	assert.Equal(t, 0, a.buttons.recognizer.FireAt, "no multi press action bound")
}

func TestSetupButtons_Validation(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(*agent.ButtonConfig){
		"action and exec": func(c *agent.ButtonConfig) {
			c.Double = actions.Spec{Action: actionReboot, Exec: []string{"/bin/true"}}
		},
		"unknown action":      func(c *agent.ButtonConfig) { c.LongPress.Action = "self-destruct" },
		"multi count too low": func(c *agent.ButtonConfig) { c.MultiPress.Count = 2 },
		"hold too short":      func(c *agent.ButtonConfig) { c.LongPress.Hold = 500 * time.Millisecond },
		"no gesture window":   func(c *agent.ButtonConfig) { c.GestureWindow = 0 },
	} {
		cfg := defaultButtonConfig()
		mutate(&cfg)
		a, _ := newButtonTestAgent(t, cfg)
		assert.Error(t, a.setupButtons(), name)
	}
}

func TestSetupButtons_BoundGestures(t *testing.T) {
	t.Parallel()

	cfg := defaultButtonConfig()
	cfg.LongPress.Action = actionShutdown
	cfg.MultiPress.Action = actionEmergencyPoweroff
	a, _ := newButtonTestAgent(t, cfg)
	require.NoError(t, a.setupButtons())

	assert.True(t, a.buttons.holdFeedback)
	assert.True(t, a.edgeLeds.Defined(ledLayerButtonHold))
	assert.Equal(t, 5, a.buttons.recognizer.FireAt)
}

// runButtons starts the button handler on a fake HAL and returns the channel to inject button events
func runButtons(t *testing.T, a *computeBladeAgent) chan hal.ButtonEvent {
	t.Helper()

	buttons := make(chan hal.ButtonEvent, 32)
	blade := &hal.ComputeBladeHalMock{}
	blade.On("ButtonEvents").Return((<-chan hal.ButtonEvent)(buttons))
	a.blade = blade

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.runButtonHandler(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		a.actions.Wait()
	})
	return buttons
}

func clickAt(buttons chan hal.ButtonEvent, source hal.ButtonSource, at time.Time) {
	buttons <- hal.ButtonEvent{Source: source, Pressed: true, Time: at}
	if source == hal.ButtonSourceEdge {
		buttons <- hal.ButtonEvent{Source: source, Pressed: false, Time: at.Add(50 * time.Millisecond)}
	}
}

// waitForGesture reads events until a gesture event arrives
func waitForGesture(t *testing.T, a *computeBladeAgent) events.GestureDetails {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case msg := <-a.eventChan:
			if msg.Event == events.ButtonGestureEvent {
				return msg.Details.(events.GestureDetails)
			}
		case <-deadline:
			t.Fatal("timed out waiting for a gesture")
		}
	}
}

func TestButtonHandler_DoublePressRunsAction(t *testing.T) {
	t.Parallel()

	cfg := defaultButtonConfig()
	cfg.Double = actions.Spec{Action: actionReboot}
	a, calls := newButtonTestAgent(t, cfg)
	require.NoError(t, a.setupButtons())
	buttons := runButtons(t, a)

	now := time.Now()
	clickAt(buttons, hal.ButtonSourceEdge, now)
	clickAt(buttons, hal.ButtonSourceEdge, now.Add(80*time.Millisecond))

	gesture := waitForGesture(t, a)
	assert.Equal(t, events.GestureDetails{Gesture: gestureDouble, Presses: 2, Action: actionReboot}, gesture)
	assert.Eventually(t, func() bool { return calls[actionReboot].Load() == 1 }, time.Second, time.Millisecond)
	assert.Equal(t, int32(0), calls[actionIdentifyToggle].Load())
}

func TestButtonHandler_UnboundGestureIsPublished(t *testing.T) {
	t.Parallel()

	a, calls := newButtonTestAgent(t, defaultButtonConfig())
	require.NoError(t, a.setupButtons())
	buttons := runButtons(t, a)

	now := time.Now()
	for i := 0; i < 3; i++ {
		clickAt(buttons, hal.ButtonSourceEdge, now.Add(time.Duration(i)*80*time.Millisecond))
	}

	gesture := waitForGesture(t, a)
	assert.Equal(t, events.GestureDetails{Gesture: gestureMultiPress, Presses: 3}, gesture)
	for name, counter := range calls {
		assert.Equal(t, int32(0), counter.Load(), name)
	}
}

func TestButtonHandler_FanUnitButtonBypassesGestures(t *testing.T) {
	t.Parallel()

	a, _ := newButtonTestAgent(t, defaultButtonConfig())
	require.NoError(t, a.setupButtons())
	buttons := runButtons(t, a)

	clickAt(buttons, hal.ButtonSourceFanUnit, time.Now())

	select {
	case msg := <-a.eventChan:
		assert.Equal(t, events.Event(events.ButtonPressEvent), msg.Event)
		assert.Equal(t, events.ButtonDetails{Source: "fan_unit"}, msg.Details)
	case <-time.After(5 * time.Second):
		t.Fatal("expected a button press event")
	}

	// no gesture follows
	select {
	case msg := <-a.eventChan:
		t.Fatalf("unexpected event %s", msg.Event)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestButtonHandler_LongPressWithFeedback(t *testing.T) {
	t.Parallel()

	cfg := defaultButtonConfig()
	cfg.LongPress = agent.LongPressConfig{Hold: 1500 * time.Millisecond, Spec: actions.Spec{Action: actionShutdown}}
	a, calls := newButtonTestAgent(t, cfg)
	require.NoError(t, a.setupButtons())
	buttons := runButtons(t, a)

	buttons <- hal.ButtonEvent{Source: hal.ButtonSourceEdge, Pressed: true, Time: time.Now()}

	// the edge LED signals the upcoming long press after the feedback delay
	assert.Eventually(t, func() bool { return a.edgeLeds.Shown() == ledLayerButtonHold }, 3*time.Second, 10*time.Millisecond)

	gesture := waitForGesture(t, a)
	assert.Equal(t, gestureLongPress, gesture.Gesture)
	assert.Equal(t, actionShutdown, gesture.Action)
	assert.GreaterOrEqual(t, gesture.Held, 1500*time.Millisecond)
	assert.Eventually(t, func() bool { return calls[actionShutdown].Load() == 1 }, time.Second, time.Millisecond)
	assert.Eventually(t, func() bool { return a.edgeLeds.Shown() == "" }, time.Second, 10*time.Millisecond)
}

func TestHandleEvent_FanUnitPressTogglesIdentify(t *testing.T) {
	t.Parallel()

	a, _ := newButtonTestAgent(t, defaultButtonConfig())
	ctx := context.Background()

	require.NoError(t, a.handleEvent(ctx, events.NewMessage(events.ButtonPressEvent, events.ButtonDetails{Source: "fan_unit"})))
	msgs := drainEvents(a.eventChan)
	require.Len(t, msgs, 1)
	assert.Equal(t, events.Event(events.IdentifyEvent), msgs[0].Event)

	// edge presses are handled by the gesture recognizer, not here
	require.NoError(t, a.handleEvent(ctx, events.NewMessage(events.ButtonPressEvent, events.ButtonDetails{Source: "edge"})))
	assert.Empty(t, drainEvents(a.eventChan))
}
