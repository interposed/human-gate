# Example: gate an interpose-sandbox launch with human-gate

[interpose-sandbox](https://github.com/interposed/interpose-sandbox) runs an
agent, a command, or a CI pipeline inside a deny-default box on a machine you
own. human-gate puts a human tap in front of that launch: nothing starts until a
real person approves, and the approval is a signed, offline-verifiable token.

human-gate does not depend on interpose-sandbox. This example only shells out to
the sandbox CLI after the approval succeeds, so the gate stays independent of the
thing it gates.

## Route / exec pattern (no code)

Wrap the launch so a tap gates it. The shipping process tier:

```sh
humangate start --method fido2 -- interpose sandbox start --tier process -- claude
```

The governed CI runner:

```sh
humangate start --method fido2 -- interpose-ci run pipeline.json --approve deny
```

If the tap is declined, `humangate` exits non-zero and the launch never runs.

## Go example

```sh
go run ./examples/interpose-sandbox -- echo "sandbox would launch here"
```

It calls `humangate.RequireApproval`, verifies the signed token offline, then
execs the launch command you pass after `--`. The demo approver auto-approves
through the `route` method; in production use `--method fido2` (or
`MethodFIDO2` in Go) so a hardware tap gates the launch.
