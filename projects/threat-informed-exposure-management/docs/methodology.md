# Methodology

## Design principles

1. **CVSS is one input.** Technical severity is capped at 15% of the score.
2. **Threat evidence changes urgency.** Known and active exploitation together contribute up to 35%.
3. **Business context matters.** Criticality, reachability, privilege, and controls determine potential impact and opportunity.
4. **Age creates accountability.** Older unresolved exposure adds limited score and can breach the remediation SLA.
5. **Every score must be explainable.** The output lists the main factors that raised priority.
6. **Closure must be validated.** A remediated item receives a validation action instead of disappearing automatically.

## Formula

The score is the sum of:

- `(CVSS / 10) × 15`
- `(asset criticality / 5) × 15`
- `20` when known exploited
- `15` when relevant active exploitation is reported
- `10` when externally reachable
- `5` when privileged
- `((100 - control coverage) / 100) × 10`
- `min(days open / 90, 1) × 5`
- when known/active exploitation evidence exists, intelligence confidence: low `1`, moderate `3`, high `5`; otherwise `0`

## Priority bands and illustrative SLAs

| Band | Score | SLA |
|---|---:|---:|
| Critical | 75–100 | 7 days |
| High | 55–74.9 | 15 days |
| Medium | 35–54.9 | 30 days |
| Low | Below 35 | 90 days |

## Governance cautions

Weights and SLAs require approval from security, technology, business owners, risk, and compliance. Intelligence must include provenance, recency, and confidence. Exceptions need owners and review dates. The production system should preserve score history so changes are auditable.

## Validation questions

- Do known-exploited, actively exploited exposures rise appropriately?
- Can a critical externally reachable asset outrank a higher-CVSS isolated asset?
- Are weak or missing controls visible in the rationale?
- Are remediated records held for closure validation?
- Can every priority be explained to the owner and leadership?
