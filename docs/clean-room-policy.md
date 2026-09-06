# Clean-room implementation and provenance policy

State slice: `security-alignment-os-foundation-v1`.

## Prohibited inputs

This repository must not copy, vendor, translate, mechanically port, or derive
hidden implementation details from:

- `/Users/shaanp/Documents/GitHub/composed-zk-benchmark-os`;
- any other local repository or worktree;
- remote repositories, private packages, or downloaded source trees;
- prior generated corpora, traces, model outputs, checkpoints, or result bundles.

The current research repository is architectural context only. Its closed
scientific artifacts and negative results are not inputs to this repository.

## Permitted SOTA inputs

An implementation may be independently authored from a public paper,
specification, protocol description, or API contract when the source record is
captured in a future provenance manifest containing:

1. source title, author, URL, revision/date, and license;
2. the exact public concepts used;
3. an independent design and implementation note;
4. a statement that no source code or restricted artifact was copied;
5. tests written against the public contract rather than a private
   implementation's behavior.

Semi-closed-source code, private model weights, restricted datasets, and
unlicensed ports are excluded unless explicit redistribution and implementation
rights are available and independently reviewed before use.

## Evidence boundary

Public-source provenance does not make an implementation secure or aligned. It
only establishes lawful and reproducible input provenance. Security claims still
require adversarial validation, independent review, and the claim ceilings in
`README.md` and `docs/threat-model.md`.

