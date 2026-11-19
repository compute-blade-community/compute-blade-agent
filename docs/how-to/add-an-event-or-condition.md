# Add an event or a health condition

*For developers.* Events are how the agent's parts talk to each other and to the outside world. A health condition is a
pair of events (raise and clear) with an LED indicator. This checklist covers every place one touches.

## An event

1. **Internal event.** Append a constant to the list in [`pkg/events/event.go`](../../pkg/events/event.go) and add its
   name to `Event.String()`. The name shows up in logs and in the `type` label of
   `computeblade_agent_events_count`. If the event carries data, add a details struct there as well.
2. **API.** Append a value to the `Event` enum in `blade.proto`. For details, add a message and a field in the
   `details` oneof of `AgentEvent`. Run `mise run generate`.
3. **Mapping.** Map the internal event to the API in `toProtoEventType` and its details in `toProtoEvent`
   ([`internal/agent/utils.go`](../../internal/agent/utils.go)). Events missing from `toProtoEventType` stay internal
   and aren't published.
4. **Handling.** If the agent has to do something when the event happens, add a case to `handleEvent` in
   [`internal/agent/handler.go`](../../internal/agent/handler.go).
5. **Emitting.** Send the event with `a.emitMessage(ctx, events.NewMessage(...))`. It never blocks: if the event loop
   is full, the event is dropped and counted.
6. **bladectl.** `bladectl events --event` learns the name from the enum by itself. Format the details for the text
   output in [`cmd/bladectl/cmd_events.go`](../../cmd/bladectl/cmd_events.go).
7. **Docs.** Add the event to [Events](../reference/events.md) and the enum table in [gRPC API](../reference/grpc-api.md).

## A health condition

A condition needs a raise and a clear event, set up as above, plus:

1. **Name.** Add a `Condition...` constant and list it in `events.Conditions`. Return the condition from
   `Event.ConditionChange()` for both events. That's enough for the agent state, the `computeblade_state_state`
   metric, `GetStatus().conditions` and the LED indicator to follow the condition.
2. **Detector.** Decide when it's raised and cleared. [`pkg/health`](../../pkg/health) has reusable detectors: a
   threshold with hysteresis, a flag that clears after a delay and the fan stall detector. Detectors are plain state
   machines that take the current time as an argument, which keeps them easy to test.
3. **Configuration.** Add an `enabled` switch and the detector's settings to `HealthConfig` in
   [`pkg/agent/config.go`](../../pkg/agent/config.go), with defaults in `SetDefaults`
   ([`pkg/agent/defaults.go`](../../pkg/agent/defaults.go)). Defaults matter: existing config files don't have the new
   keys.
4. **Indicator.** Add default indicator settings with `setIndicatorDefaults`. Pick `led: none` if the condition is
   common in normal operation, so blades don't blink for no reason.
5. **Docs.** Document the condition in [Configuration file](../reference/configuration.md),
   [LEDs](../reference/leds.md), [Metrics](../reference/metrics.md) and
   [Health conditions and critical mode](../explanation/health-and-critical-mode.md), and add it to
   `cmd/agent/default-config.yaml`.

## Test

- Detector logic: table tests in `pkg/health`, with explicit times.
- Wiring: see `internal/agent/health_test.go` and `leds_test.go`, which drive events through `handleEvent` against
  the HAL mock and check state, LEDs and published events.
- Hardware: [Run a development build on a blade](test-on-a-blade.md).
