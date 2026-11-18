package internal_agent

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/actions"
	"github.com/compute-blade-community/compute-blade-agent/pkg/agent"
	"github.com/compute-blade-community/compute-blade-agent/pkg/button"
	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/compute-blade-community/compute-blade-agent/pkg/ledengine"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"github.com/sierrasoftworks/humane-errors-go"
	"go.uber.org/zap"
)

const (
	// Built-in actions
	actionNone              = "none"
	actionIdentifyToggle    = "identify-toggle"
	actionShutdown          = "shutdown"
	actionReboot            = "reboot"
	actionEmergencyPoweroff = "emergency-poweroff"

	// Gesture names, as published in events and passed to exec actions
	gestureSingle     = "single"
	gestureDouble     = "double"
	gestureMultiPress = "multi_press"
	gestureLongPress  = "long_press"

	// ledLayerButtonHold blinks the edge LED while the button is held towards a long press
	ledLayerButtonHold    = "button_hold"
	ledPriorityButtonHold = 1500
	// holdFeedbackDelay is how long the button has to be held before the LED starts signalling an upcoming long press
	holdFeedbackDelay = time.Second
)

// buttonBindings is the validated button configuration
type buttonBindings struct {
	cfg        agent.ButtonConfig
	recognizer button.Config
	// holdFeedback is true if a long press runs an action, so holding the button gets LED feedback
	holdFeedback bool
}

// newActionRunner creates the runner for button actions with the agent's built-in actions.
func (a *computeBladeAgent) newActionRunner() *actions.Runner {
	return actions.NewRunner(map[string]actions.Builtin{
		actionNone: func(context.Context) error { return nil },
		actionIdentifyToggle: func(ctx context.Context) error {
			event := events.Event(events.IdentifyEvent)
			if a.state.IdentifyActive() {
				event = events.IdentifyConfirmEvent
			}
			a.emitEvent(ctx, event)
			return nil
		},
		actionShutdown: func(ctx context.Context) error {
			log.FromContext(ctx).Warn("Shutting down the blade (button action)")
			return runSystemCommand(ctx, []string{"systemctl", "poweroff"}, []string{"shutdown", "-h", "now"})
		},
		actionReboot: func(ctx context.Context) error {
			log.FromContext(ctx).Warn("Rebooting the blade (button action)")
			return runSystemCommand(ctx, []string{"systemctl", "reboot"}, []string{"shutdown", "-r", "now"})
		},
		actionEmergencyPoweroff: emergencyPoweroff,
	})
}

// runSystemCommand runs the first command whose binary exists.
func runSystemCommand(ctx context.Context, candidates ...[]string) error {
	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate[0])
		if err != nil {
			continue
		}
		output, err := exec.CommandContext(ctx, path, candidate[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v failed: %w: %s", candidate, err, output)
		}
		return nil
	}
	return errors.New("neither systemctl nor shutdown found")
}

// setupButtons validates the button configuration.
func (a *computeBladeAgent) setupButtons() error {
	cfg := a.config.Button

	// a single press toggles identify unless configured otherwise
	if cfg.Single.IsZero() {
		cfg.Single = actions.Spec{Action: actionIdentifyToggle}
	}

	if cfg.GestureWindow <= 0 {
		return humane.New("button.gesture_window must be positive", "e.g. 400ms")
	}
	if cfg.LongPress.Hold <= holdFeedbackDelay {
		return humane.New(fmt.Sprintf("button.long_press.hold must be longer than %s", holdFeedbackDelay), "e.g. 5s")
	}
	if cfg.MultiPress.Count < 3 {
		return humane.New("button.multi_press.count must be at least 3", "1 and 2 presses are the single and double gestures")
	}

	for name, spec := range map[string]actions.Spec{
		gestureSingle:     cfg.Single,
		gestureDouble:     cfg.Double,
		gestureLongPress:  cfg.LongPress.Spec,
		gestureMultiPress: cfg.MultiPress.Spec,
	} {
		if err := a.actions.Validate(spec); err != nil {
			return humane.Wrap(err, fmt.Sprintf("invalid action for button.%s", name))
		}
	}

	bound := func(s actions.Spec) bool { return !s.IsZero() && s.Action != actionNone }

	recognizer := button.Config{
		Window:       cfg.GestureWindow,
		LongPress:    cfg.LongPress.Hold,
		HoldFeedback: holdFeedbackDelay,
	}
	// React immediately when the multi press count is reached, e.g. for an emergency power-off
	if bound(cfg.MultiPress.Spec) {
		recognizer.FireAt = cfg.MultiPress.Count
	}

	a.buttons = buttonBindings{
		cfg:          cfg,
		recognizer:   recognizer,
		holdFeedback: bound(cfg.LongPress.Spec),
	}

	if a.buttons.holdFeedback {
		if err := a.edgeLeds.Define(ledLayerButtonHold, ledPriorityButtonHold,
			ledengine.NewFastBlinkPattern(led.Color{}, led.Color{Red: 32, Green: 32, Blue: 32})); err != nil {
			return err
		}
	}

	return nil
}

// gestureBinding returns the gesture name and the configured action for a recognised gesture.
func (b buttonBindings) gestureBinding(g button.Gesture) (string, actions.Spec) {
	switch {
	case g.Long:
		return gestureLongPress, b.cfg.LongPress.Spec
	case g.Presses == 1:
		return gestureSingle, b.cfg.Single
	case g.Presses == 2:
		return gestureDouble, b.cfg.Double
	case g.Presses == b.cfg.MultiPress.Count:
		return gestureMultiPress, b.cfg.MultiPress.Spec
	default:
		// a series with a count nothing is bound to; still published
		return gestureMultiPress, actions.Spec{}
	}
}

// runButtonHandler turns button transitions into gestures and runs the bound actions until ctx is done.
func (a *computeBladeAgent) runButtonHandler(ctx context.Context) {
	log.FromContext(ctx).Info("Starting button handler")

	recognizer := button.NewRecognizer(a.buttons.recognizer)
	buttonEvents := a.blade.ButtonEvents()

	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()

	for {
		if deadline, ok := recognizer.NextDeadline(time.Now()); ok {
			timer.Reset(time.Until(deadline))
		}

		var gestures []button.Gesture
		select {
		case <-ctx.Done():
			return
		case ev := <-buttonEvents:
			gestures = a.handleButtonEvent(ctx, recognizer, ev)
		case now := <-timer.C:
			gestures = recognizer.Tick(now)
		}
		timer.Stop()

		a.setHoldFeedback(ctx, recognizer.Holding(time.Now()))
		for _, g := range gestures {
			a.handleGesture(ctx, g)
		}
	}
}

// handleButtonEvent publishes presses and feeds edge button transitions into the recognizer.
func (a *computeBladeAgent) handleButtonEvent(ctx context.Context, recognizer *button.Recognizer, ev hal.ButtonEvent) []button.Gesture {
	if ev.Pressed {
		a.emitMessage(ctx, events.Message{
			Event:     events.ButtonPressEvent,
			Timestamp: ev.Time,
			Details:   events.ButtonDetails{Source: ev.Source.String()},
		})
	}

	// The fan unit button only toggles identify (handled with the press event); the fan unit firmware already uses
	// the number of presses to pick the blade, so it can't do gestures.
	if ev.Source != hal.ButtonSourceEdge {
		return nil
	}

	if ev.Pressed {
		return recognizer.Press(ev.Time)
	}
	return recognizer.Release(ev.Time)
}

// handleGesture publishes a gesture and runs its action.
func (a *computeBladeAgent) handleGesture(ctx context.Context, g button.Gesture) {
	name, spec := a.buttons.gestureBinding(g)

	log.FromContext(ctx).Info("Button gesture",
		zap.String("gesture", name),
		zap.Int("presses", g.Presses),
		zap.Duration("held", g.Held),
		zap.String("action", spec.Describe()),
	)

	a.emitMessage(ctx, events.NewMessage(events.ButtonGestureEvent, events.GestureDetails{
		Gesture: name,
		Presses: g.Presses,
		Held:    g.Held,
		Action:  spec.Describe(),
	}))

	a.actions.Run(ctx, "button."+name, spec, map[string]string{
		"BLADE_EVENT":       "button_gesture",
		"BLADE_GESTURE":     name,
		"BLADE_PRESS_COUNT": strconv.Itoa(g.Presses),
		"BLADE_HOLD_MS":     strconv.FormatInt(g.Held.Milliseconds(), 10),
		"BLADE_HOSTNAME":    a.hostname,
	})
}

// setHoldFeedback blinks the edge LED while the button is held towards a long press that runs an action.
func (a *computeBladeAgent) setHoldFeedback(ctx context.Context, holding bool) {
	if !a.buttons.holdFeedback {
		return
	}

	var err error
	if holding {
		err = a.edgeLeds.Activate(ledLayerButtonHold)
	} else {
		err = a.edgeLeds.Deactivate(ledLayerButtonHold)
	}
	if err != nil {
		log.FromContext(ctx).WithError(err).Warn("Failed to update button hold feedback")
	}
}
