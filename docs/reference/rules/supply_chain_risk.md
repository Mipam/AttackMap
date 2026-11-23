# `supply_chain_risk`

Dependency supply-chain risk

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | 0.8 (high band) |
| CWE | - |
| Tags | supply-chain, dependency-risk |
| Replaces legacy detector ids | dependency-confusion, typosquat-candidate, mutable-vcs-dependency, install-script, unlocked-manifest, insecure-registry |

## Why this rule fires

A manifest, lockfile or package-manager config contains a positively-present supply-chain risk — an internal-looking name resolvable from a public registry, a one-edit distance from a popular package, a mutable VCS pin, an install hook, a missing lockfile/integrity hash, or plain-HTTP registry traffic. Per-kind CWE tags are attached to each finding from the taxonomy.

## Evidence expectations

Dependency supply-chain findings beyond CVEs (#247), one per kind.

Equivalent port of the legacy branch: dependency-confusion, typosquat,
mutable VCS/URL pins, install scripts, unlocked manifests and insecure
registries aggregate per kind with the max instance severity; only the
typosquat kind keeps the legacy ``medium`` confidence band.
