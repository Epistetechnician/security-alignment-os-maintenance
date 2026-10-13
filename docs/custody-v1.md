# Custody and retention records V1

State slice: `security-alignment-os-foundation-v1`.

`custody::CustodyRoot` records an owner assertion, a digest of the root
declaration, the required `0700` mode assertion, repository-external status,
and finite root/raw-retention intervals. The root locator and raw bytes are not
stored. Raw retention is capped at 72 hours in this local contract.

`CustodyRegistry` requires the declared owner to declare each record and a
distinct validator assertion. `require_active` binds an exact artifact digest,
live root interval, and unexpired raw-retention interval. `require_artifact`
also binds the manifest root identifier. The artifact-bound integration
workflow requires these checks before admission. `mark_deleted` is terminal and
owner-only. Registry `validate`, `save`, `load`, and `recover` enforce lifecycle
consistency and canonical JSON snapshots through the shared atomic snapshot
helper.

`verify_local_artifact` adds a read-only local file check. It binds the logical
record to the manifest root ID and artifact digest, requires the custody root
to be a real `0700` directory outside the caller-supplied repository anchor,
and rejects traversal, symlinked path components, non-regular files, multiple
hard links, broad Unix permissions, foreign UID ownership, files over the
caller-supplied byte limit, and bytes whose SHA-256 differs from the manifest.
On Unix it opens each root and artifact directory component relative to an
already-open directory handle with symlink following disabled. It opens the
final file the same way, hashes it with a bounded reader, and checks its device,
inode, owner, mode, link count, size, change time, and modification time before
and after the read. The verifier obtains the expected host UID from the
process's effective UID; `LocalCustodyPaths` only holds transient path and byte
limit inputs, which are never persisted.

The `integration::run_with_local_artifact_and_receipt` entry point runs this
physical check before admission and receipt verification. Failure quarantines
before admission or runtime mutation, so a corrected file can be retried with
the same receipt. Existing artifact-bound entry points continue to provide only
logical registry checks.

These are caller-owned local checks. Descriptor-relative opens prevent symlink
redirection during the component walk, and the final open handle pins the file
identity being checked. They do not make file contents immutable or map the
declared owner identity to the process effective UID. A process running under
that UID can still change filesystem state before the check. Retention is not
enforced, files are not erased, and external custody is not proved. The
filesystem path anchor and byte limit are caller supplied.
Missing, expired, mismatched, duplicate, malformed, inaccessible, or unsafe
data fails closed; secure deletion is not provided.
