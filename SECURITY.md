# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
"Report a vulnerability" (private security advisory) feature on this
repository. Do not open a public issue for an unfixed vulnerability.

Include the affected path or component, a minimal reproduction, and the impact
you observe. Expect an acknowledgement; this is a research project maintained on
a best-effort basis and no response-time guarantee is offered.

## Scope and claim boundary

This is research software. It has not been independently audited. Passing tests,
local replays, and self-reviews described in this repository are not security
guarantees. See `RESEARCH.md` for what each result does and does not establish.

## Secrets

The repository is scanned for credentials before release. If you find a secret,
credential, or personal data in the tree or history, report it using the process
above so it can be rotated and removed.
