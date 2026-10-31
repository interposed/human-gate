# Example: gate a nono launch with human-gate

human-gate is a standalone, aauth-native human-in-the-loop approval gate. It is
not coupled to nono: nono is just one tool you might put a tap in front of. This
example shows human-gate gating a nono agent launch; it imports `human-gate`,
never the other way around.

## Two ways to wire it in

1. Wrapper (works today, needs nothing from nono) - gate the launch, then run
   nono:

   ```sh
   humangate start --method fido2 -- nono run claude-code
   ```

   A tap gates the launch; nono only runs if the approval succeeds.

2. Hook (preferred, if nono exposes an approval/event hook) - point nono at
   `humangate start ...` as the approver. human-gate signals its decision by exit
   code (0 approve, non-zero refuse), so it drops into any exec-style hook.

## Run the Go example

```sh
go run ./examples/nono
```

It auto-approves through the `route` method (shelling out to `true`) and prints
the signed, offline-verifiable token. Swap the demo approver for
`MethodFIDO2` + the fido2 bridge for a real hardware tap - see the top-level
`examples/README.md`.
