package main

import (
	"bytes"
	"encoding/json"
	"testing"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventPrinter_JSONKeepsZeroValueEvent(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	p := &eventPrinter{out: &out, json: true}
	p.print("blade-test", &bladeapiv1alpha1.AgentEvent{Event: bladeapiv1alpha1.Event_IDENTIFY, Blade: "blade-test"})

	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.Equal(t, "IDENTIFY", got["event"])
	assert.Equal(t, "blade-test", got["blade"])
}
