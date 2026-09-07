# Custody and retention records V1

State slice: `security-alignment-os-foundation-v1`.

`custody::CustodyRoot` records an owner assertion, a digest of the root
declaration, the required `0700` mode assertion, repository-external status,
and finite root/raw-retention intervals. The root locator and raw bytes are not
stored. Raw retention is capped at 72 hours in this local contract.

`CustodyRegistry` requires the declared owner to declare each record and a
distinct validator assertion. `require_active` binds an exact artifact digest
and live root interval. `mark_deleted` is terminal and owner-only. Registry
`validate`, `save`, `load`, and `recover` enforce lifecycle consistency and
canonical JSON snapshots through a temporary path.

These are caller-owned records. They do not authenticate the owner or
validator, inspect OS permissions, enforce retention, erase bytes, or prove
external custody. Missing, expired, mismatched, duplicate, or malformed data
fails closed.
