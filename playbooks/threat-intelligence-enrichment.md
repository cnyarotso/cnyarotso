# Threat-Intelligence Enrichment Playbook

## Objective

Turn a local indicator or behavior into relevant, time-bounded context without treating reputation as proof.

## Required intelligence fields

| Field | Purpose |
|---|---|
| Indicator/TTP | Normalized match value or behavior |
| Source | Provenance and reliability |
| First/last seen | Recency and campaign timing |
| Confidence | Strength of the assessment and rationale |
| Threat/campaign | Operational context |
| Expiration/review date | Prevents stale intelligence from driving permanent action |
| Local observation | Evidence that the indicator or behavior appeared internally |

## Workflow

1. Normalize the indicator or behavior.
2. Record the intelligence source before copying conclusions.
3. Compare source reliability, confidence, age, and shared-infrastructure risk.
4. Correlate with local endpoint, identity, email, DNS, proxy, or network evidence.
5. Join asset criticality, vulnerability, reachability, ownership, and control coverage.
6. Decide whether to hunt, block, contain, remediate, monitor, or close.
7. Set an expiration/review date for IOC-based controls.

## Confidence rule

A third-party match raises a hypothesis. Corroborated local behavior, relevant exposure, and multiple trustworthy sources raise confidence. Stale, low-confidence, or shared infrastructure lowers it.
