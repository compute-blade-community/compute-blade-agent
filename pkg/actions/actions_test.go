package actions_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/actions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRunner(calls *atomic.Int32, block chan struct{}) *actions.Runner {
	return actions.NewRunner(map[string]actions.Builtin{
		"shutdown": func(context.Context) error {
			calls.Add(1)
			if block != nil {
				<-block
			}
			return nil
		},
		"reboot": func(context.Context) error { return nil },
	})
}

func TestValidate(t *testing.T) {
	t.Parallel()

	r := newRunner(&atomic.Int32{}, nil)

	assert.NoError(t, r.Validate(actions.Spec{}))
	assert.NoError(t, r.Validate(actions.Spec{Action: "shutdown"}))
	assert.NoError(t, r.Validate(actions.Spec{Exec: []string{"/bin/true"}, Timeout: time.Second}))

	assert.ErrorContains(t, r.Validate(actions.Spec{Action: "shutdown", Exec: []string{"/bin/true"}}), "not both")
	assert.ErrorContains(t, r.Validate(actions.Spec{Action: "self-destruct"}), "reboot, shutdown")
	assert.Error(t, r.Validate(actions.Spec{Exec: []string{""}}))
	assert.Error(t, r.Validate(actions.Spec{Exec: []string{"/bin/true"}, Timeout: -time.Second}))
}

func TestDescribe(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "", actions.Spec{}.Describe())
	assert.Equal(t, "shutdown", actions.Spec{Action: "shutdown"}.Describe())
	assert.Equal(t, "exec", actions.Spec{Exec: []string{"/bin/true"}}.Describe())
}

func TestRun_Builtin(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	r := newRunner(&calls, nil)

	assert.True(t, r.Run(context.Background(), "button.long_press", actions.Spec{Action: "shutdown"}, nil))
	r.Wait()
	assert.Equal(t, int32(1), calls.Load())
}

func TestRun_DropsWhileRunning(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	block := make(chan struct{})
	r := newRunner(&calls, block)
	ctx := context.Background()

	assert.True(t, r.Run(ctx, "key", actions.Spec{Action: "shutdown"}, nil))
	assert.Eventually(t, func() bool { return calls.Load() == 1 }, time.Second, time.Millisecond)

	// same key while running: dropped. Other keys are independent.
	assert.False(t, r.Run(ctx, "key", actions.Spec{Action: "shutdown"}, nil))
	assert.True(t, r.Run(ctx, "other", actions.Spec{Action: "reboot"}, nil))

	close(block)
	r.Wait()
	assert.Equal(t, int32(1), calls.Load())

	// finished: the key can run again
	assert.True(t, r.Run(ctx, "key", actions.Spec{Action: "reboot"}, nil))
	r.Wait()
}

func TestRun_ExecWithEnvironment(t *testing.T) {
	t.Parallel()

	out := filepath.Join(t.TempDir(), "out")
	r := newRunner(&atomic.Int32{}, nil)

	spec := actions.Spec{Exec: []string{"/bin/sh", "-c", `printf '%s %s' "$BLADE_GESTURE" "$1" > "$OUT"`, "sh", "arg1"}}
	require.True(t, r.Run(context.Background(), "key", spec, map[string]string{"BLADE_GESTURE": "double", "OUT": out}))
	r.Wait()

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "double arg1", strings.TrimSpace(string(raw)))
}

func TestRun_ExecTimeout(t *testing.T) {
	t.Parallel()

	r := newRunner(&atomic.Int32{}, nil)
	start := time.Now()
	require.True(t, r.Run(context.Background(), "key", actions.Spec{Exec: []string{"/bin/sleep", "10"}, Timeout: 100 * time.Millisecond}, nil))
	r.Wait()
	assert.Less(t, time.Since(start), 5*time.Second)
}
