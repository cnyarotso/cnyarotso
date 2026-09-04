# Detection Validation Playbook

## Objective

Demonstrate that a detection receives the required telemetry, matches expected behavior, avoids unacceptable noise, and produces an actionable response.

## Validation stages

1. **Data contract:** document required table/index, event type, fields, retention, and expected latency.
2. **Known-positive test:** run an authorized simulation or replay sanitized evidence.
3. **Field validation:** confirm timestamps, entities, parent/child relationships, and normalization.
4. **Negative test:** confirm expected business behavior does not match.
5. **Historical test:** measure volume, affected entities, and false-positive patterns.
6. **Threshold tuning:** baseline by asset role, segment, identity type, and time window.
7. **Alert routing:** confirm severity, ownership, enrichment, and notification delivery.
8. **Triage test:** verify that an analyst can reproduce the evidence and reach a disposition.
9. **Control-health monitoring:** alert when the telemetry or rule stops producing expected data.

## Measures

- Expected test events detected
- Data latency and missing-field rate
- Alert volume and unique entities
- False-positive rate and documented exclusions
- Median time to analyst disposition
- Percentage of alerts with an assigned owner and next action
- Detection coverage mapped to supported ATT&CK behavior

## Release decision

A detection is production-ready only when its data dependency, expected matches, false positives, severity, owner, response steps, and health monitoring are documented.
