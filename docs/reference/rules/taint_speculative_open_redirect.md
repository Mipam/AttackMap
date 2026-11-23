# `taint_speculative_open_redirect`

Speculative reach to a redirect target sink (recall mode)

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | 0.3 (low band) |
| CWE | CWE-601 |
| OWASP / ASVS | A01:2021 · V5.1.5 |
| ATT&CK | [T1204.001](https://attack.mitre.org/techniques/T1204/001/), [T1566.002](https://attack.mitre.org/techniques/T1566/002/) |
| Tags | taint-chain, speculative, recall |
| Replaces legacy detector ids | speculative-open-redirect |

## Why this rule fires

Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for redirect target.

## Evidence expectations

Recall-mode speculative reach to one sink kind: clearly-marked,
low-severity leads for ``--hunt --verify`` to adjudicate — never asserted
flows, kept out of the ``--fail-on-new-high`` gate (legacy #148a block).
Speculative chains of the flow-family kinds produce nothing, exactly as
in the legacy bucketing (the flow gate `continue`s before the
speculative bucket).
