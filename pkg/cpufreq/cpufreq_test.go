package cpufreq_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compute-blade-community/compute-blade-agent/pkg/cpufreq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSysfs creates a cpufreq sysfs tree with one policy (CM4-like: 600 MHz - 1.5 GHz)
func fakeSysfs(t *testing.T) (root string, policyDir string) {
	t.Helper()

	root = t.TempDir()
	policyDir = filepath.Join(root, "sys/devices/system/cpu/cpufreq/policy0")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))

	for name, value := range map[string]string{
		"cpuinfo_min_freq":            "600000",
		"cpuinfo_max_freq":            "1500000",
		"scaling_max_freq":            "1500000",
		"scaling_governor":            "ondemand",
		"scaling_available_governors": "conservative ondemand userspace powersave performance schedutil",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(policyDir, name), []byte(value+"\n"), 0o644))
	}
	return root, policyDir
}

func read(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return strings.TrimSpace(string(raw))
}

func TestController_ApplyAndRestore(t *testing.T) {
	t.Parallel()

	root, policy := fakeSysfs(t)
	statePath := filepath.Join(t.TempDir(), "run", "cpufreq.json")

	c, err := cpufreq.New(root, statePath)
	require.NoError(t, err)

	require.NoError(t, c.Apply(cpufreq.Limits{Governor: "powersave", MaxFreqKHz: 1200000}))
	assert.Equal(t, "powersave", read(t, filepath.Join(policy, "scaling_governor")))
	assert.Equal(t, "1200000", read(t, filepath.Join(policy, "scaling_max_freq")))
	assert.FileExists(t, statePath)

	require.NoError(t, c.Restore())
	assert.Equal(t, "ondemand", read(t, filepath.Join(policy, "scaling_governor")))
	assert.Equal(t, "1500000", read(t, filepath.Join(policy, "scaling_max_freq")))
	assert.NoFileExists(t, statePath)
}

func TestController_ClampsFrequency(t *testing.T) {
	t.Parallel()

	root, policy := fakeSysfs(t)
	c, err := cpufreq.New(root, "")
	require.NoError(t, err)

	require.NoError(t, c.Apply(cpufreq.Limits{MaxFreqKHz: 100000}))
	assert.Equal(t, "600000", read(t, filepath.Join(policy, "scaling_max_freq")), "clamped to cpuinfo_min_freq")
	assert.Equal(t, "ondemand", read(t, filepath.Join(policy, "scaling_governor")), "governor untouched")

	require.NoError(t, c.Apply(cpufreq.Limits{MaxFreqKHz: 3000000}))
	assert.Equal(t, "1500000", read(t, filepath.Join(policy, "scaling_max_freq")), "never raised above the original max")
}

func TestController_RecoversOriginalsAfterCrash(t *testing.T) {
	t.Parallel()

	root, policy := fakeSysfs(t)
	statePath := filepath.Join(t.TempDir(), "cpufreq.json")

	first, err := cpufreq.New(root, statePath)
	require.NoError(t, err)
	require.NoError(t, first.Apply(cpufreq.Limits{Governor: "powersave", MaxFreqKHz: 1000000}))

	// The agent crashes without restoring. A new instance must not take the limited values as originals.
	second, err := cpufreq.New(root, statePath)
	require.NoError(t, err)
	require.NoError(t, second.Restore())

	assert.Equal(t, "ondemand", read(t, filepath.Join(policy, "scaling_governor")))
	assert.Equal(t, "1500000", read(t, filepath.Join(policy, "scaling_max_freq")))
}

func TestController_Validate(t *testing.T) {
	t.Parallel()

	root, _ := fakeSysfs(t)
	c, err := cpufreq.New(root, "")
	require.NoError(t, err)

	assert.NoError(t, c.Validate(cpufreq.Limits{Governor: "powersave"}))
	assert.NoError(t, c.Validate(cpufreq.Limits{MaxFreqKHz: 1000000}))
	assert.Error(t, c.Validate(cpufreq.Limits{Governor: "turbo"}))
}

func TestNew_NotSupported(t *testing.T) {
	t.Parallel()

	_, err := cpufreq.New(t.TempDir(), "")
	assert.ErrorIs(t, err, cpufreq.ErrNotSupported)
}
