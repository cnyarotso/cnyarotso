# Alert Triage Playbook

## Objective

Convert an alert into a documented decision while protecting evidence and avoiding premature attribution.

## Workflow

1. **Validate the alert:** confirm the rule, time window, data source, ingestion health, and field extraction.
2. **Identify the entities:** user, host, source/destination, process, application, and business service.
3. **Establish a timeline:** include precursor, alerting, and follow-on activity.
4. **Test the hypothesis:** state what would confirm or reject the suspected behavior.
5. **Add context:** baseline, asset criticality, vulnerability, identity privilege, control coverage, and intelligence.
6. **Check false positives:** approved scanning, service accounts, maintenance, shared infrastructure, and known business workflows.
7. **Assign a disposition:** benign, expected, suspicious, likely malicious, confirmed malicious, or inconclusive.
8. **Take action:** close, monitor, tune, hunt, contain, remediate, or escalate.
9. **Validate:** confirm that the action changed risk or visibility as intended.

## Minimum report

| Field | Required content |
|---|---|
| Alert and time | Rule name, first/last seen, timezone |
| Entities | User, device, IP/domain, process, application |
| Evidence | Queries, event IDs, screenshots, hashes, or log references |
| Assessment | Observed facts, interpretation, confidence, and alternatives |
| Impact | Asset/business importance and affected scope |
| Decision | Disposition and severity |
| Action | Owner, deadline/SLA, containment or remediation |
| Validation | Query, rescan, or control test proving closure |
