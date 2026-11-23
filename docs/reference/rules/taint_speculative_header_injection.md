# `taint_speculative_header_injection`

Speculative reach to a HTTP response header sink (recall mode)

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | 0.3 (low band) |
| CWE | CWE-113 |
| OWASP / ASVS | A03:2021 |
| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Tags | taint-chain, speculative, recall |
| Replaces legacy detector ids | speculative-header-injection |

## Why this rule fires

Recall mode widens taint discovery (deeper hops, relaxed gates); every reach it adds is unconfirmed until a verifier adjudicates it, so it must be reported separately and can never clear the HIGH bar. Ported 1:1 from the legacy speculative block for HTTP response header.

## Evidence expectations

Recall-mode speculative reach to one sink kind: clearly-marked,
low-severity leads for ``--hunt --verify`` to adjudicate — never asserted
flows, kept out of the ``--fail-on-new-high`` gate (legacy #148a block).
Speculative chains of the flow-family kinds produce nothing, exactly as
in the legacy bucketing (the flow gate `continue`s before the
speculative bucket).
