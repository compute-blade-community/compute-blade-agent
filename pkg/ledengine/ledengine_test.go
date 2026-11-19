package ledengine_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/compute-blade-community/compute-blade-agent/pkg/ledengine"
	"github.com/compute-blade-community/compute-blade-agent/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewStaticPattern(t *testing.T) {
	t.Parallel()

	type args struct {
		color led.Color
	}
	tests := []struct {
		name string
		args args
		want ledengine.BlinkPattern
	}{
		{
			"Green",
			args{led.Color{Green: 255}},
			ledengine.BlinkPattern{
				BaseColor:   led.Color{Green: 255},
				ActiveColor: led.Color{Green: 255},
				Delays:      []time.Duration{time.Hour},
			},
		},
		{
			"Red",
			args{led.Color{Red: 255}},
			ledengine.BlinkPattern{
				BaseColor:   led.Color{Red: 255},
				ActiveColor: led.Color{Red: 255},
				Delays:      []time.Duration{time.Hour},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ledengine.NewStaticPattern(tt.args.color); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewStaticPattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewBurstPattern(t *testing.T) {
	t.Parallel()
	type args struct {
		baseColor  led.Color
		burstColor led.Color
	}
	tests := []struct {
		name string
		args args
		want ledengine.BlinkPattern
	}{
		{
			"Green <-> Red",
			args{
				baseColor:  led.Color{Green: 255},
				burstColor: led.Color{Red: 255},
			},
			ledengine.BlinkPattern{
				BaseColor:   led.Color{Green: 255},
				ActiveColor: led.Color{Red: 255},
				Delays: []time.Duration{
					500 * time.Millisecond, // 750ms off
					100 * time.Millisecond, // 100ms on
					100 * time.Millisecond, // 100ms off
					100 * time.Millisecond, // 100ms on
					100 * time.Millisecond, // 100ms off
					100 * time.Millisecond, // 100ms on
				},
			},
		},
		{
			"Green <-> Green (valid, but no visual effect)",
			args{
				baseColor:  led.Color{Green: 255},
				burstColor: led.Color{Green: 255},
			},
			ledengine.BlinkPattern{
				BaseColor:   led.Color{Green: 255},
				ActiveColor: led.Color{Green: 255},
				Delays: []time.Duration{
					500 * time.Millisecond, // 750ms off
					100 * time.Millisecond, // 100ms on
					100 * time.Millisecond, // 100ms off
					100 * time.Millisecond, // 100ms on
					100 * time.Millisecond, // 100ms off
					100 * time.Millisecond, // 100ms on
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ledengine.NewBurstPattern(tt.args.baseColor, tt.args.burstColor); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewBurstPattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewLedEngine(t *testing.T) {
	t.Parallel()
	engine := ledengine.Options{
		Clock:  util.RealClock{},
		LedIdx: 0,
		Hal:    &hal.ComputeBladeHalMock{},
	}
	assert.NotNil(t, engine)
}

func TestLedEngine_NewLedEngineWithoutClock(t *testing.T) {
	opts := ledengine.Options{
		Clock:  nil,
		LedIdx: 0,
		Hal:    &hal.ComputeBladeHalMock{},
	}

	engine := ledengine.NewLedEngine(opts)
	assert.NotNil(t, engine)
}

// signal returns a channel and a mock hook closing it, so a test can wait for a mocked call instead of sleeping
func signal() (chan struct{}, func(mock.Arguments)) {
	ch := make(chan struct{})
	var once sync.Once
	return ch, func(mock.Arguments) { once.Do(func() { close(ch) }) }
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func Test_LedEngine_SetPattern_WhileRunning(t *testing.T) {
	t.Parallel()

	clk := util.MockClock{}
	clkAfterChan := make(chan time.Time)
	clk.On("After", time.Hour).Times(2).Return(clkAfterChan)

	started, onStarted := signal()
	applied, onApplied := signal()
	cbMock := hal.ComputeBladeHalMock{}
	cbMock.On("SetLed", hal.LedTop, led.Color{Green: 0, Blue: 0, Red: 0}).Once().Return(nil).Run(onStarted)
	cbMock.On("SetLed", hal.LedTop, led.Color{Green: 0, Blue: 0, Red: 255}).Once().Return(nil).Run(onApplied)

	opts := ledengine.Options{
		Hal:    &cbMock,
		Clock:  &clk,
		LedIdx: 0,
	}

	engine := ledengine.NewLedEngine(opts)

	ctx, cancel := context.WithCancel(context.Background())

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := engine.Run(ctx)
		assert.ErrorIs(t, err, context.Canceled)
	}()

	// Change the pattern once the engine shows the initial one
	waitFor(t, started, "the initial pattern")
	err := engine.SetPattern(ledengine.NewStaticPattern(led.Color{Red: 255}))
	assert.NoError(t, err)

	// Cancel only after the engine applied the new pattern: with both ready, select would pick either at random
	waitFor(t, applied, "the new pattern")
	cancel()
	wg.Wait()

	clk.AssertExpectations(t)
	cbMock.AssertExpectations(t)
}

func Test_LedEngine_SetPattern_BeforeRun(t *testing.T) {
	t.Parallel()

	clk := util.MockClock{}
	clkAfterChan := make(chan time.Time)
	waiting, onWaiting := signal()
	clk.On("After", time.Hour).Once().Return(clkAfterChan).Run(onWaiting)

	cbMock := hal.ComputeBladeHalMock{}
	cbMock.On("SetLed", hal.LedTop, led.Color{Green: 0, Blue: 0, Red: 255}).Once().Return(nil)

	opts := ledengine.Options{
		Hal:    &cbMock,
		Clock:  &clk,
		LedIdx: 0,
	}

	engine := ledengine.NewLedEngine(opts)
	// We want to change the pattern BEFORE the engine is started
	err := engine.SetPattern(ledengine.NewStaticPattern(led.Color{Red: 255}))
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := engine.Run(ctx)
		assert.ErrorIs(t, err, context.Canceled)
	}()

	// The engine applied the pattern and waits for its delay
	waitFor(t, waiting, "the engine to wait for the pattern's delay")
	cancel()
	wg.Wait()

	clk.AssertExpectations(t)
	cbMock.AssertExpectations(t)
}

func Test_LedEngine_SetPattern_SetLedFailureInPattern(t *testing.T) {
	t.Parallel()

	clk := util.MockClock{}
	clkAfterChan := make(chan time.Time)
	clk.On("After", time.Hour).Once().Return(clkAfterChan)

	cbMock := hal.ComputeBladeHalMock{}
	call0 := cbMock.On("SetLed", hal.LedTop, led.Color{Green: 0, Blue: 0, Red: 0}).Once().Return(nil)
	cbMock.On("SetLed", hal.LedTop, led.Color{Green: 0, Blue: 0, Red: 0}).Once().Return(errors.New("failure")).NotBefore(call0)

	opts := ledengine.Options{
		Hal:    &cbMock,
		Clock:  &clk,
		LedIdx: 0,
	}

	engine := ledengine.NewLedEngine(opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		err := engine.Run(ctx)
		assert.Error(t, err)
	}()

	// Time tick -> SetLed() fails -> Run returns. The send blocks until the engine waits for the tick.
	select {
	case clkAfterChan <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the engine to wait for a tick")
	}
	waitFor(t, done, "Run to return the SetLed error")

	clk.AssertExpectations(t)
	cbMock.AssertExpectations(t)
}

func Test_LedEngine_SetPattern_NoDelay(t *testing.T) {
	t.Parallel()

	clk := util.MockClock{}
	clkAfterChan := make(chan time.Time)
	clk.On("After", time.Hour).Once().Return(clkAfterChan)

	cbMock := hal.ComputeBladeHalMock{}
	cbMock.On("SetLed", hal.LedTop, led.Color{Green: 0, Blue: 0, Red: 255}).Once().Return(nil)

	opts := ledengine.Options{
		Hal:    &cbMock,
		Clock:  &clk,
		LedIdx: 0,
	}

	engine := ledengine.NewLedEngine(opts)
	invalidPattern := ledengine.NewStaticPattern(led.Color{Red: 255})
	invalidPattern.Delays = []time.Duration{}
	// We want to change the pattern BEFORE the engine is started
	t.Log("Setting pattern")
	err := engine.SetPattern(invalidPattern)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "pattern must have at least one delay")
}
