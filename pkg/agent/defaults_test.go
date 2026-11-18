package agent_test

import (
	"strings"
	"testing"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/agent"
	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadConfigWithLegacy(t *testing.T, yaml string) (agent.ComputeBladeAgentConfig, []string) {
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

func loadConfig(t *testing.T, yaml string) agent.ComputeBladeAgentConfig {
	t.Helper()

	cfg, _ := loadConfigWithLegacy(t, yaml)
	return cfg
}

func TestSetDefaults_LedColors(t *testing.T) {
	t.Parallel()

	cfg, legacy := loadConfigWithLegacy(t, "stealth_mode: false\n")
	assert.Empty(t, legacy)
	assert.Equal(t, led.Color{Green: 16}, cfg.IdleLedColor)
	assert.Equal(t, led.Color{Red: 16, Blue: 16}, cfg.IdentifyLedColor)
	assert.Equal(t, led.Color{Red: 64}, cfg.CriticalLedColor)
}

func TestMigrateLegacyKeys_CriticalLedColor(t *testing.T) {
	t.Parallel()

	cfg, legacy := loadConfigWithLegacy(t, "criticalLedColor:\n  red: 32\n  green: 1\n  blue: 2\n")
	assert.Equal(t, []string{"criticalLedColor"}, legacy)
	assert.Equal(t, led.Color{Red: 32, Green: 1, Blue: 2}, cfg.CriticalLedColor)
}

func TestMigrateLegacyKeys_CurrentKeyWins(t *testing.T) {
	t.Parallel()

	cfg, legacy := loadConfigWithLegacy(t, "criticalLedColor:\n  red: 32\ncritical_led_color:\n  red: 128\n")
	assert.Equal(t, []string{"criticalLedColor"}, legacy)
	assert.Equal(t, led.Color{Red: 128}, cfg.CriticalLedColor)
}

func TestSetDefaults_MissingKeys(t *testing.T) {
	t.Parallel()

	cfg := loadConfig(t, "stealth_mode: false\n")

	assert.True(t, cfg.Health.FanStall.Enabled)
	assert.Equal(t, uint8(20), cfg.Health.FanStall.MinPercent)
	assert.Equal(t, 15*time.Second, cfg.Health.FanStall.GracePeriod)

	indicator, ok := cfg.Indicators[events.ConditionFanStall]
	require.True(t, ok)
	assert.Equal(t, agent.IndicatorLedTop, indicator.Led)
	assert.Equal(t, "fast-blink", indicator.Pattern)
	assert.Equal(t, led.Color{Red: 64, Green: 24}, indicator.Color)
}

func TestSetDefaults_PartialOverride(t *testing.T) {
	t.Parallel()

	cfg := loadConfig(t, `
health:
  fan_stall:
    grace_period: 30s
indicators:
  fan_stall:
    led: edge
`)

	// overridden
	assert.Equal(t, 30*time.Second, cfg.Health.FanStall.GracePeriod)
	assert.Equal(t, agent.IndicatorLedEdge, cfg.Indicators[events.ConditionFanStall].Led)
	// kept from defaults
	assert.True(t, cfg.Health.FanStall.Enabled)
	assert.Equal(t, "fast-blink", cfg.Indicators[events.ConditionFanStall].Pattern)
	assert.Equal(t, 30, cfg.Indicators[events.ConditionFanStall].Priority)
}
