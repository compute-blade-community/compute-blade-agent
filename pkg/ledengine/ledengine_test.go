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

func Test_LedEngine_SetPattern_WhileRunning(t *testing.T) {
	t.Parallel()

	clk := util.MockClock{}
	clkAfterChan := make(chan time.Time)
	clk.On("After", time.Hour).Times(2).Return(clkAfterChan)

	cbMock := hal.ComputeBladeHalMock{}
	cbMock.On("SetLed", uint(0), led.Color{Green: 0, Blue: 0, Red: 0}).Once().Return(nil)
	cbMock.On("SetLed", uint(0), led.Color{Green: 0, Blue: 0, Red: 255}).Once().Return(nil)

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
		t.Log("LedEngine.Run() started")
		err := engine.Run(ctx)
		assert.ErrorIs(t, err, context.Canceled)
		t.Log("LedEngine.Run() exited")
	}()

	// We want to change the pattern while the engine is running
	time.Sleep(5 * time.Millisecond)

	// Set pattern
	t.Log("Setting pattern")
	err := engine.SetPattern(ledengine.NewStaticPattern(led.Color{Red: 255}))
	assert.NoError(t, err)

	t.Log("Canceling context")
	cancel()
	wg.Wait()

	clk.AssertExpectations(t)
	cbMock.AssertExpectations(t)
}

func Test_LedEngine_SetPattern_BeforeRun(t *testing.T) {
	t.Parallel()

	clk := util.MockClock{}
	clkAfterChan := make(chan time.Time)
	clk.On("After", time.Hour).Once().Return(clkAfterChan)

	cbMock := hal.ComputeBladeHalMock{}
	cbMock.On("SetLed", uint(0), led.Color{Green: 0, Blue: 0, Red: 255}).Once().Return(nil)

	opts := ledengine.Options{
		Hal:    &cbMock,
		Clock:  &clk,
		LedIdx: 0,
	}

	engine := ledengine.NewLedEngine(opts)
	// We want to change the pattern BEFORE the engine is started
	t.Log("Setting pattern")
	err := engine.SetPattern(ledengine.NewStaticPattern(led.Color{Red: 255}))
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		t.Log("LedEngine.Run() started")
		err := engine.Run(ctx)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		t.Log("LedEngine.Run() exited")
	}()

	t.Log("Waiting for context to timeout")
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
	call0 := cbMock.On("SetLed", uint(0), led.Color{Green: 0, Blue: 0, Red: 0}).Once().Return(nil)
	cbMock.On("SetLed", uint(0), led.Color{Green: 0, Blue: 0, Red: 0}).Once().Return(errors.New("failure")).NotBefore(call0)

	opts := ledengine.Options{
		Hal:    &cbMock,
		Clock:  &clk,
		LedIdx: 0,
	}

	engine := ledengine.NewLedEngine(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		t.Log("LedEngine.Run() started")
		err := engine.Run(ctx)
		assert.Error(t, err)
		t.Log("LedEngine.Run() exited")
	}()
	time.Sleep(5 * time.Millisecond)

	// Time tick -> SetLed() fails
	clkAfterChan <- time.Now()

	t.Log("Waiting for context to timeout")
	wg.Wait()

	clk.AssertExpectations(t)
	cbMock.AssertExpectations(t)
}
