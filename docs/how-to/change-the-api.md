# Change the gRPC API

*For developers.*

The API is defined in [`api/bladeapi/v1alpha1/blade.proto`](../../api/bladeapi/v1alpha1/blade.proto). The Go code
next to it is generated and committed.

## Make the change

1. Edit `blade.proto`.
2. Regenerate the code:

   ```bash
   mise run generate
   ```

   buf runs the protoc plugins pinned in `mise.toml` locally, no network access needed.
3. Implement new RPCs in [`internal/agent/api.go`](../../internal/agent/api.go) and use them in `bladectl`
   ([`cmd/bladectl`](../../cmd/bladectl)).
4. Commit the `.proto` file and the generated code together. CI runs `mise run generate:check` and fails if they
   don't match.

## Keep old clients working

`bladectl` versions and agent versions mix in practice: people upgrade their workstation and their blades at
different times. Even though the API is `v1alpha1`, avoid breaking changes:

- Add fields and enum values, don't renumber or remove them. Retire a field with `reserved`.
- Give new fields a zero value that means "not set" or "same as before".
- Don't change the type of an existing field. The wire format of some types is compatible, the generated code isn't.
- New RPCs are fine. An old agent answers them with `Unimplemented`, handle that in `bladectl`.

`IDENTIFY` being the zero value of `Event` is a historical accident. JSON encoders drop zero values by default, so
`bladectl` sets `EmitDefaultValues` when it prints events. Do the same in other JSON output.

Avoid 64-bit integer fields for values that fit into 32 bits: the protobuf JSON mapping turns `int64` into strings.

## Test it

[`internal/agent/api_events_test.go`](../../internal/agent/api_events_test.go) shows how to test an RPC against an
agent over an in-memory connection (`bufconn`), without hardware.
