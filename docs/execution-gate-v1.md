# External execution gate V1

State slice: `security-alignment-os-foundation-v1`.

`execution_gate` defines the records required before a future external
executor could be considered: a time-bounded sandbox attestation with egress
denial, secret-broker, independent-kill and resource-limit declarations, plus a
request binding program, input, output schema, proof system, privacy
requirement, deadline and price ceiling.

`ExecutionGate::authorize` validates every field and returns a typed
`GateDecision`. Valid requests are still `Blocked` because this foundation
slice has no external authorization path. Invalid or expired records return a
hard error before any external action. The module never starts processes,
opens sockets, brokers credentials, contacts providers, or claims that a
caller-declared attestation was enforced.

Validation:

```text
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

Opening this gate later requires a fresh state slice, an exact executor
identity, authenticated attestation verification, a positive user-authorized
spend ceiling, independent review, and provider-specific custody and recovery
evidence.
