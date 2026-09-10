# Preregistered causal protocol V1

State slice: `security-alignment-os-foundation-v1`.

`causal::CausalProtocol` freezes behavioral, mechanistic, or scalable-oversight
track identity together with model, runtime, assets, corpus and split
digests; held-out split; wrapper, feature, estimand, intervention and control;
power, multiplicity, repeat and attrition plans; prediction lock; custody; and
validator configuration. Researcher and validator identities must differ.

The state order is `Draft -> Qualified -> AssessmentLocked -> Accepted`, with
an explicit terminal `Closed` state. Qualification must precede assessment
locking. Assessment locking must name the exact prediction lock digest.
Independent acceptance must name the configured validator. Raw traces are
never stored; only a retention deadline and aggregate evidence digests are
recorded.

This is a preregistration and acceptance-order contract only. It does not load
a model, run an intervention, retain scientific traces, or establish a causal,
alignment, consciousness, introspection, or human-benefit claim.
