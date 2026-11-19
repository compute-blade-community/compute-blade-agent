// Package cpufreq limits the CPU frequency through the Linux cpufreq sysfs interface.
package cpufreq

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// ErrNotSupported is returned when the system exposes no cpufreq policies.
var ErrNotSupported = errors.New("cpufreq is not supported on this system")

// Limits restricts the CPU. Zero values mean "no restriction" (keep the original setting).
type Limits struct {
	// Governor is the cpufreq governor to use, e.g. powersave
	Governor string `json:"governor,omitempty"`
	// MaxFreqKHz caps the CPU frequency in kHz
	MaxFreqKHz uint64 `json:"max_freq_khz,omitempty"`
}

// IsZero reports whether the limits restrict nothing.
func (l Limits) IsZero() bool {
	return l.Governor == "" && l.MaxFreqKHz == 0
}

// policy is one cpufreq policy (a group of CPUs that share a clock)
type policy struct {
	dir        string
	minFreqKHz uint64
	// original settings, restored when no limits apply
	Governor   string `json:"governor"`
	MaxFreqKHz uint64 `json:"max_freq_khz"`
}

// Controller applies Limits to all cpufreq policies and restores the original settings when they are lifted.
type Controller struct {
	policies   []*policy
	governors  []string
	statePath  string
	applied    Limits
	hasApplied bool
	// recovered is set if the originals were taken from the state file of a previous instance
	recovered bool
}

// New discovers the cpufreq policies under root ("/" on a real system).
//
// The original governor and maximum frequency are saved to statePath (absolute, e.g. on /run) before any limit is
// applied. If the agent crashes while limits are applied, the next instance restores the settings from that file
// instead of mistaking the limited values for the originals. statePath may be empty to disable this.
func New(root string, statePath string) (*Controller, error) {
	dirs, err := filepath.Glob(filepath.Join(root, "sys/devices/system/cpu/cpufreq/policy*"))
	if err != nil || len(dirs) == 0 {
		return nil, ErrNotSupported
	}
	slices.Sort(dirs)

	saved := loadState(statePath)

	c := &Controller{statePath: statePath}
	for _, dir := range dirs {
		p := &policy{dir: dir}

		if p.minFreqKHz, err = readUint(filepath.Join(dir, "cpuinfo_min_freq")); err != nil {
			return nil, err
		}

		if original, ok := saved[filepath.Base(dir)]; ok {
			p.Governor, p.MaxFreqKHz = original.Governor, original.MaxFreqKHz
			c.recovered = true
		} else {
			if p.Governor, err = readString(filepath.Join(dir, "scaling_governor")); err != nil {
				return nil, err
			}
			if p.MaxFreqKHz, err = readUint(filepath.Join(dir, "scaling_max_freq")); err != nil {
				return nil, err
			}
		}

		c.policies = append(c.policies, p)
	}

	if raw, err := readString(filepath.Join(dirs[0], "scaling_available_governors")); err == nil {
		c.governors = strings.Fields(raw)
	}

	return c, nil
}

// Recovered reports whether a previous instance left limits behind: the original settings were read from its state
// file instead of the current (possibly limited) values. Restore puts them back.
func (c *Controller) Recovered() bool {
	return c.recovered
}

// AvailableGovernors returns the governors the kernel offers.
func (c *Controller) AvailableGovernors() []string {
	return c.governors
}

// Validate checks that the limits can be applied on this system.
func (c *Controller) Validate(l Limits) error {
	if l.Governor != "" && len(c.governors) > 0 && !slices.Contains(c.governors, l.Governor) {
		return fmt.Errorf("governor %q is not available, available governors: %s", l.Governor, strings.Join(c.governors, ", "))
	}
	return nil
}

// Apply restricts all policies to the given limits; zero values restore the original setting. Frequencies are clamped
// to what each policy supports.
func (c *Controller) Apply(l Limits) error {
	if c.hasApplied && c.applied == l {
		return nil
	}

	if !l.IsZero() {
		if err := c.saveState(); err != nil {
			return fmt.Errorf("failed to save original cpufreq settings: %w", err)
		}
	}

	var errs []error
	for _, p := range c.policies {
		governor := p.Governor
		if l.Governor != "" {
			governor = l.Governor
		}

		maxFreq := p.MaxFreqKHz
		if l.MaxFreqKHz != 0 {
			maxFreq = min(max(l.MaxFreqKHz, p.minFreqKHz), p.MaxFreqKHz)
		}

		errs = append(errs,
			writeString(filepath.Join(p.dir, "scaling_governor"), governor),
			writeString(filepath.Join(p.dir, "scaling_max_freq"), strconv.FormatUint(maxFreq, 10)),
		)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}

	c.applied, c.hasApplied = l, true

	if l.IsZero() {
		c.removeState()
	}
	return nil
}

// Restore puts back the original settings.
func (c *Controller) Restore() error {
	return c.Apply(Limits{})
}

func (c *Controller) saveState() error {
	if c.statePath == "" {
		return nil
	}

	state := make(map[string]policy, len(c.policies))
	for _, p := range c.policies {
		state[filepath.Base(p.dir)] = *p
	}

	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.statePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(c.statePath, raw, 0o644)
}

func (c *Controller) removeState() {
	if c.statePath != "" {
		_ = os.Remove(c.statePath)
	}
}

func loadState(path string) map[string]policy {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var state map[string]policy
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil
	}
	return state
}

func readString(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func readUint(path string) (uint64, error) {
	raw, err := readString(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(raw, 10, 64)
}

func writeString(path string, value string) error {
	return os.WriteFile(path, []byte(value), 0o644)
}
