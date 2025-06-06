package util_test

import (
	"testing"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/util"

	"github.com/stretchr/testify/assert"
)

// TestRealClock_Now ensures that RealClock.Now() returns a time close to the actual time.
func TestRealClock_Now(t *testing.T) {
	rc := util.RealClock{}
	before := time.Now()
	got := rc.Now()
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Errorf("RealClock.Now() = %v, want between %v and %v", got, before, after)
	}
}

// TestRealClock_After ensures that RealClock.After() returns a channel that sends after the given duration.
func TestRealClock_After(t *testing.T) {
	rc := util.RealClock{}
	delay := 50 * time.Millisecond

	start := time.Now()
	ch := rc.After(delay)
	<-ch
	elapsed := time.Since(start)

	if elapsed < delay {
		t.Errorf("RealClock.After(%v) triggered too early after %v", delay, elapsed)
	}
}

// TestMockClock_Now tests that MockClock.Now() returns the expected time and records the call.
func TestMockClock_Now(t *testing.T) {
	mockClock := new(util.MockClock)
	expectedTime := time.Date(2025, time.June, 6, 12, 0, 0, 0, time.UTC)

	mockClock.On("Now").Return(expectedTime)

	actualTime := mockClock.Now()
	assert.Equal(t, expectedTime, actualTime)
	mockClock.AssertCalled(t, "Now")
	mockClock.AssertExpectations(t)
}

// TestMockClock_After tests that MockClock.After() returns the expected channel and records the call.
func TestMockClock_After(t *testing.T) {
	mockClock := new(util.MockClock)
	duration := 100 * time.Millisecond
	expectedChan := make(chan time.Time, 1)
	expectedTime := time.Now().Add(duration)
	expectedChan <- expectedTime

	mockClock.On("After", duration).Return(expectedChan)

	resultChan := mockClock.After(duration)
	select {
	case result := <-resultChan:
		assert.WithinDuration(t, expectedTime, result, time.Second)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for result from MockClock.After")
	}

	mockClock.AssertCalled(t, "After", duration)
	mockClock.AssertExpectations(t)
}
