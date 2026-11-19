package agent_test

import (
	"strings"
	"testing"

	"github.com/compute-blade-community/compute-blade-agent/pkg/agent"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadConfig(t *testing.T, yaml string) (agent.ComputeBladeAgentConfig, []string) {
	t.Helper()

	v := viper.New()
	v.SetConfigType("yaml")
	agent.SetDefaults(v)
	require.NoError(t, v.ReadConfig(strings.NewReader(yaml)))
	legacy := agent.MigrateLegacyKeys(v)

	var cfg agent.ComputeBladeAgentConfig
	require.NoError(t, v.Unmarshal(&cfg))
	return cfg, legacy
}

func TestSetDefaults_LedColors(t *testing.T) {
	t.Parallel()

	cfg, legacy := loadConfig(t, "stealth_mode: false\n")
	assert.Empty(t, legacy)
	assert.Equal(t, led.Color{Green: 16}, cfg.IdleLedColor)
	assert.Equal(t, led.Color{Red: 16, Blue: 16}, cfg.IdentifyLedColor)
	assert.Equal(t, led.Color{Red: 64}, cfg.CriticalLedColor)
}

func TestMigrateLegacyKeys_CriticalLedColor(t *testing.T) {
	t.Parallel()

	cfg, legacy := loadConfig(t, "criticalLedColor:\n  red: 32\n  green: 1\n  blue: 2\n")
	assert.Equal(t, []string{"criticalLedColor"}, legacy)
	assert.Equal(t, led.Color{Red: 32, Green: 1, Blue: 2}, cfg.CriticalLedColor)
}

func TestMigrateLegacyKeys_CurrentKeyWins(t *testing.T) {
	t.Parallel()

	cfg, legacy := loadConfig(t, "criticalLedColor:\n  red: 32\ncritical_led_color:\n  red: 128\n")
	assert.Equal(t, []string{"criticalLedColor"}, legacy)
	assert.Equal(t, led.Color{Red: 128}, cfg.CriticalLedColor)
}
