# React to events from scripts and programs

The agent publishes every event to the `WatchEvents` stream. Anything that can read the stream can react to what
happens on a blade: a shell script, a chat notification, a Kubernetes controller.

## From a shell script

`bladectl events -o json` prints one JSON object per line and reconnects by itself when a blade restarts. `-A`
watches all blades in your bladectl config at once:

```bash
bladectl events -A -o json --event fan_stall --event undervoltage |
while read -r line; do
  blade=$(jq -r '.blade' <<<"$line")
  event=$(jq -r '.event' <<<"$line")
  logger -t blade-health "$blade: $event"
done
```

The JSON follows the [`AgentEvent`](../reference/grpc-api.md#agentevent) message. Event names are upper case there
(`FAN_STALL`), `--event` takes them in lower case.

## Bind your own behaviour to a button gesture

Gestures without an action are still published. Leave `double` unbound in the agent's config and handle it from a
machine that has `kubectl`:

```bash
bladectl events -A -o json --event button_gesture |
jq --unbuffered -r 'select(.gesture.gesture == "double") | .blade' |
while read -r blade; do
  kubectl cordon "$blade" && kubectl drain "$blade" --ignore-daemonsets --delete-emptydir-data
done
```

Someone at the rack double-presses the edge button, the node drains, and they can pull the blade once the workloads
moved.

## From a Go program

[`examples/watch-events`](../../examples/watch-events/main.go) is a complete client. It reads the address and mTLS
credentials from the bladectl config, subscribes to the health events and reconnects when the stream ends:

```bash
go run ./examples/watch-events --blade blade-pi1         # health events only
go run ./examples/watch-events --blade blade-pi1 --all   # everything
```

The core is a single call:

```go
stream, err := client.WatchEvents(ctx, &bladeapiv1alpha1.WatchEventsRequest{
    Events: []bladeapiv1alpha1.Event{bladeapiv1alpha1.Event_FAN_STALL},
})
for {
    ev, err := stream.Recv()
    if err != nil {
        break // agent restarted or connection lost: reconnect
    }
    fmt.Println(ev.GetBlade(), ev.GetEvent(), ev.GetFan().GetRpm())
}
```

## Things to keep in mind

The stream has no history. After connecting, call `GetStatus` (or `bladectl get status`) to learn which conditions are
already raised, then follow the events.

A slow consumer misses events once it falls 64 events behind. Raise and clear events come in pairs, so if you missed
one, `GetStatus` tells you the current state.

The agent closes the stream when it shuts down. Reconnect with a short delay, as `bladectl events` does.
