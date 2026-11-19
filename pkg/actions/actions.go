// Package actions runs what the user configured to happen in response to an event: either one of the agent's
// built-in actions, or an arbitrary command.
package actions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
)

// DefaultTimeout is how long an exec action may run if the spec doesn't set a timeout
const DefaultTimeout = 30 * time.Second

// maxLoggedOutput caps how much of a command's output is logged
const maxLoggedOutput = 4096

// Spec is a configured action: exactly one of Action (a built-in action) or Exec (a command) is set.
// An empty Spec means "do nothing".
type Spec struct {
	// Action is the name of a built-in action, e.g. shutdown
	Action string `mapstructure:"action"`
	// Exec is a command and its arguments. It is run directly, not through a shell.
	Exec []string `mapstructure:"exec"`
	// Timeout limits how long Exec may run (default 30s). The command is killed when it expires.
	Timeout time.Duration `mapstructure:"timeout"`
}

// IsZero reports whether the spec does nothing.
func (s Spec) IsZero() bool {
	return s.Action == "" && len(s.Exec) == 0
}

// Describe returns a short description for logs and events: the action name, "exec", or "" for none.
func (s Spec) Describe() string {
	switch {
	case s.Action != "":
		return s.Action
	case len(s.Exec) > 0:
		return "exec"
	default:
		return ""
	}
}

// Builtin is a built-in action.
type Builtin func(ctx context.Context) error

// Runner runs actions asynchronously. Each key (e.g. a button gesture) runs at most one action at a time: a trigger
// while the previous action of the same key is still running is dropped.
type Runner struct {
	builtins map[string]Builtin

	mu      sync.Mutex
	running map[string]bool
	wg      sync.WaitGroup
}

// NewRunner creates a Runner with the given built-in actions.
func NewRunner(builtins map[string]Builtin) *Runner {
	return &Runner{
		builtins: builtins,
		running:  make(map[string]bool),
	}
}

// Builtins returns the names of the built-in actions, sorted.
func (r *Runner) Builtins() []string {
	names := make([]string, 0, len(r.builtins))
	for name := range r.builtins {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Validate checks a spec: at most one of action and exec, a known action, a non-empty command.
func (r *Runner) Validate(s Spec) error {
	if s.Action != "" && len(s.Exec) > 0 {
		return errors.New("set either action or exec, not both")
	}
	if s.Action != "" {
		if _, ok := r.builtins[s.Action]; !ok {
			return fmt.Errorf("unknown action %q, must be one of: %s", s.Action, strings.Join(r.Builtins(), ", "))
		}
	}
	if len(s.Exec) > 0 && strings.TrimSpace(s.Exec[0]) == "" {
		return errors.New("exec needs a command")
	}
	if s.Timeout < 0 {
		return errors.New("timeout must not be negative")
	}
	return nil
}

// Run starts the action in the background. env is added to the environment of exec actions.
// Returns false if the action was dropped because the previous action of the same key is still running.
func (r *Runner) Run(ctx context.Context, key string, s Spec, env map[string]string) bool {
	if s.IsZero() {
		return true
	}

	r.mu.Lock()
	if r.running[key] {
		r.mu.Unlock()
		log.FromContext(ctx).Warn("Action still running, dropping trigger", zap.String("key", key), zap.String("action", s.Describe()))
		return false
	}
	r.running[key] = true
	r.mu.Unlock()

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() {
			r.mu.Lock()
			delete(r.running, key)
			r.mu.Unlock()
		}()

		logger := log.FromContext(ctx).With(zap.String("key", key), zap.String("action", s.Describe()))
		logger.Info("Running action")

		var err error
		if s.Action != "" {
			err = r.builtins[s.Action](ctx)
		} else {
			err = runExec(ctx, s, env)
		}

		if err != nil {
			logger.WithError(err).Error("Action failed")
			return
		}
		logger.Info("Action finished")
	}()

	return true
}

// Wait blocks until all running actions finished. Meant for tests and shutdown.
func (r *Runner) Wait() {
	r.wg.Wait()
}

func runExec(ctx context.Context, s Spec, env map[string]string) error {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, s.Exec[0], s.Exec[1:]...)
	cmd.Env = os.Environ()
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cmd.Env = append(cmd.Env, k+"="+env[k])
	}
	// Don't wait forever for output pipes held open by processes the command started in the background
	cmd.WaitDelay = 5 * time.Second

	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		out := string(output)
		if len(out) > maxLoggedOutput {
			out = out[:maxLoggedOutput] + "... (truncated)"
		}
		log.FromContext(ctx).Info("Action output", zap.Strings("command", s.Exec), zap.String("output", strings.TrimSpace(out)))
	}

	if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("command timed out after %s: %w", timeout, err)
	}
	return err
}
