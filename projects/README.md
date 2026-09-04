# Cybersecurity Projects

These projects are organized as analyst case studies rather than tool demonstrations. Each one states the question, evidence, decision, confidence boundary, and next action.

## Recommended reading order

### 1. [Threat-Informed Exposure Prioritization Engine](threat-informed-exposure-management/)

Combines vulnerability severity, known exploitation, local threat evidence, reachability, asset criticality, privileged access, control gaps, and exposure age into a transparent priority score. Includes synthetic data, runnable Python, ranked output, tests, and remediation SLAs.

**Skills:** exposure management, CTI operationalization, risk scoring, Python automation, executive metrics, remediation governance.

### 2. [Zeek-to-Splunk Network Threat Hunting Lab](https://github.com/cnyarotso/SocLab)

Transforms packet data into Zeek telemetry, parses it in Splunk, tests network-hunting hypotheses, and distinguishes expected mDNS activity from leads requiring more context.

**Skills:** Zeek, Splunk, SPL, PCAP analysis, detection engineering, false-positive reasoning, analyst reporting.

### 3. [Follina Malware Triage & Detection](https://github.com/cnyarotso/Folina_Malware_Triage_Project)

Uses safe static analysis to turn suspicious Office-document evidence into behavioral detections, hunting pivots, asset-exposure questions, and remediation actions.

**Skills:** malware triage, evidence handling, Sigma, KQL, SPL, ATT&CK mapping, exposure prioritization.

## Documentation standard

New projects use the [case-study template](project-case-study-template.md) so reviewers can compare work consistently.

## Development roadmap

A Microsoft Sentinel investigation project will be promoted here after its public repository includes the underlying KQL, sanitized evidence, incident timeline, analytic-rule logic, tuning notes, and disposition. It is intentionally not presented as a completed featured project before those artifacts are reviewable.
