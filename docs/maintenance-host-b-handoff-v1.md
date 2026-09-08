# Host B handoff: fixed maintenance replication

State slice: `security-alignment-os-foundation-v1`.

This document is for the independently administered Host B operator. It
produces one signed Host B report for the already frozen maintenance
operation. It does not authorize a new operation, adaptation, model
execution, market activity, or production change.

## Acceptance boundary

Host B must be a separate physical macOS host controlled by the separate
operator. The operator must run the commands locally on Host B. A gateway,
remote shell, account switch on Host A, or a second device label is not a
substitute for independent execution and custody.

Host B is acceptable only if all of these remain true:

- Host B reports `Darwin arm64`.
- Host B uses the exact source revision and toolchain bindings below.
- The evaluator executable digest matches exactly.
- Host B has separate host and operator signing keys.
- The evaluator key is provisioned by its independent evaluator custodian;
  Host A seeds are never copied to Host B.
- Host B keeps its checkout, keys, and raw evidence private.
- The operator identity and physical Host B identity are authenticated out of
  band by the approving parties.

If any condition cannot be verified, stop and report `Inconclusive`. Do not
edit the frozen bundle or manufacture a report.

## Frozen bindings

These values must match Host B exactly:

```text
state_slice                 security-alignment-os-foundation-v1
operation                   normalize-trailing-ascii-spaces-v1
process_version             2
implementation_revision     188f2f20652794e1594a0adc6de51b828fa5a966
toolchain_digest            d60e324b40ad860f7c4b5254c5682bd1a92a801ed7f76296ddda35bb09377dc1
evaluator_digest             def0c3fe72f0482fb5b35147daf63b9369549eb97bc87f6283ab21083328c022
evaluator_input_digest      e39abbd9730f515e0ea2bf1cb759da74fbf248624f6034fa33a13951fa37c947
evaluator_tests_digest      52dda37989fde70c329e1c9e1f217ed8cdd37c40fe9e26a46098d502a37fe33c
policy_digest               aa447d86e31061b499b806a4922ee3f8463e88dcc51e198daffba1bcb89a5f32
request_digest              bf05003203d3c9d31714a2c2fe77fede3bacc4e00b693637424cb898d851f49d
checkout_baseline_digest    9d5e8e92614f40f52fff079dcc3e7b408c9b19af7f6e059e1ce47474184ddf43
baseline_manifest_digest    43ed24b5b1aeb6c42c9ef35be63e35e64e35ba9df52fd1733548a44a7b265cf9
evaluator_public_key        e7029b3e7431737f136e448407f9871e33c6b76248e122f2b41eb2e972253b63
evaluator_timeout_ms        10000
request_lease_expires_at    4102444800
request_nonce               1
```

The canonical frozen request and two-file baseline manifest are in the Host A
bundle. Obtain that bundle through an approved private channel and verify its
SHA-256 against the digest supplied separately by Host A. Do not use a public
URL, shared paste, or unverified gateway artifact.

Host A bundle on the originating workstation (use the path supplied out of
band; do not copy this workstation path literally):

```text
<HOST_A_FROZEN_BUNDLE_PATH>
```

## 1. Verify Host B locally

On the MacBook Air, using the Gmail operator account and its local terminal:

```sh
uname -srm
tailscale status
rustc -Vv
```

Record the output privately. The first command must identify `Darwin arm64`.
Do not treat Tailscale presence alone as host attestation; record the physical
device identity through the approved out-of-band procedure.

## 2. Obtain the exact source revision

Transfer the source through an approved private channel. A Git bundle is
acceptable. On Host A, the bundle must be created from the clean checkout at
the frozen revision. On Host B:

```sh
git clone /private/path/maintenance-188f2f2.bundle /private/path/maintenance-host-b
cd /private/path/maintenance-host-b
git checkout --detach 188f2f20652794e1594a0adc6de51b828fa5a966
git status --short
git rev-parse HEAD
```

The status must be empty and the revision must equal the frozen revision.

## 3. Build and compare the evaluator

Use the same approved Rust installation as Host A. Do not accept a merely
similar compiler version. Capture the exact bytes and compare the digest:

```sh
cd /private/path/maintenance-host-b
rustc -Vv > /private/path/host-b-toolchain.txt
shasum -a 256 /private/path/host-b-toolchain.txt
cargo build --release --bins
shasum -a 256 target/release/maintenance_evaluator
pnpm run lint
```

The toolchain digest must be
`d60e324b40ad860f7c4b5254c5682bd1a92a801ed7f76296ddda35bb09377dc1` and the
evaluator digest must be
`def0c3fe72f0482fb5b35147daf63b9369549eb97bc87f6283ab21083328c022`. A
mismatch is `Inconclusive`; do not copy an evaluator binary to hide a build
mismatch.

## 4. Create Host B custody

Use a private artifact root outside the checkout. Host B must retain this root
and its raw evidence. Do not place it in a shared repository or gateway
workspace.

Generate only Host B's own signing keys:

```sh
./target/release/maintenance_replication_runner keygen-host \
  /private/path/host-b-keys
```

The evaluator seed is different custody. The evaluator custodian must
provision the already frozen evaluator seed through the approved secret
procedure at a private path such as
`/private/path/evaluator-keys/evaluator.seed`. Never obtain it from Host A's
report directory and never include it in the handoff response.

## 5. Initialize and run the real Host B matrix

Create an operator-owned checkout matching the frozen two-file manifest. The
checkout must contain the exact `README.md` and `neighbor.txt` bytes described
by `frozen-bundle.json`, with no links, hardlinks, special files, or extra
regular files.

Initialize Host B with a distinct stable host/operator label. Use `contender`
for the cross-state lock scenario because Host A is the `winner` report:

```sh
./target/release/maintenance_replication_runner init \
  /private/path/host-b-checkout \
  /private/path/host-b-artifacts \
  /private/path/maintenance-host-b/target/release/maintenance_broker \
  /private/path/maintenance-host-b/target/release/maintenance_evaluator \
  /private/path/evaluator-keys/evaluator.seed \
  host-b \
  operator-b \
  /private/path/host-b-keys/host.seed \
  /private/path/host-b-keys/operator.seed \
  188f2f20652794e1594a0adc6de51b828fa5a966 \
  4102444800 \
  1 \
  contender \
  /private/path/host-b-spec.json
```

Run the full real-process matrix:

```sh
./target/release/maintenance_replication_runner report \
  /private/path/host-b-spec.json
```

The command must create `host-b-artifacts/report.json`, 20 private raw
evidence records, and isolated scenario artifacts. An unexpected result,
digest relation, recovery status, or signature must abort report creation.

## 6. Return only the canonical report

Before returning anything, verify privately:

```sh
shasum -a 256 /private/path/host-b-artifacts/report.json
jq '{implementation_revision,toolchain_digest,evaluator_executable_digest,evaluator_input_digest,evaluator_tests_digest,policy_digest,request_digest,checkout_baseline_digest,baseline_manifest_digest,host_id,operator_id}' \
  /private/path/host-b-artifacts/report.json
```

Return to Host A only:

- the canonical `report.json`;
- its SHA-256 digest;
- the Host B frozen-bundle SHA-256 digest used for the run;
- the non-secret attestation references for operator identity, host identity,
  evaluator custody, and evidence custody;
- the `pnpm run lint` result and toolchain/evaluator digest results.

Do not return Host B seeds, raw evidence, private key material, passwords,
session tokens, or private evidence paths.

## 7. Host A packet assembly

Host A combines the unchanged frozen bundle, Host A report, and Host B report:

```sh
./target/release/maintenance_replication_runner packet \
  /path/to/frozen-bundle.json \
  /path/to/host-a-report.json \
  /path/to/host-b-report.json \
  /private/path/replication-packet.json

./target/release/maintenance_replication_verifier \
  /private/path/replication-packet.json
```

The local verifier should report `valid_local_packet` and
`verdict: Inconclusive`. That is expected: the local verifier checks packet
consistency and signatures, while the external operator and custody
attestations determine whether the separate-host gate can close.

## Stop conditions

Stop and report `Inconclusive` if the Air is not independently administered,
the Air is not `Darwin arm64`, any frozen digest differs, the evaluator seed
custody is not independently authenticated, evidence custody is not separate,
the report is incomplete, or any scenario does not match the required result
and recovery disposition.

Do not proceed to adaptation, model execution, execution markets, settlement,
or production deployment from this handoff.
