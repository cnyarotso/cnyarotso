# Telemetry Map

## Purpose

A detection is only as defensible as its data source. This map records what is currently visible, what question the telemetry can answer, and which correlation source is still missing.

| Data source | Status | Primary fields or evidence | Question answered | Important gap |
|---|---|---|---|---|
| Zeek `conn.log` | Publicly demonstrated | Source/destination, port, protocol, bytes, duration, connection state | Which systems communicated and how? | No initiating process or user |
| Zeek `dns.log` | Publicly summarized | Query, answer, response code, host, time | What names were requested? | A lookup does not prove connection or execution |
| Zeek TLS/X.509 | Generated; deeper analysis pending | Server name, certificate, issuer, validity | What encrypted service or certificate was observed? | Payload remains encrypted |
| Windows process creation | Detection content published; event evidence pending | Parent/child image, command line, user, hash | What executed and from which parent? | Requires complete endpoint telemetry |
| Windows authentication | Planned public integration | User, host, logon type, result, source address | Was identity activity expected? | Service accounts and normal baselines |
| Microsoft Sentinel | Planned public integration | Normalized cloud/identity/endpoint events | Can cross-source evidence form an incident timeline? | Connector health and schema validation |
| Vulnerability/asset data | Demonstrated with synthetic data | CVE/CVSS, exploitation, criticality, exposure, controls, owner | Which exposure deserves action first? | Production CMDB and scanner integration |
| Threat intelligence | Design published | Indicator/TTP, source, confidence, first/last seen, expiration | Is local activity linked to relevant recent threat evidence? | Stale or shared infrastructure can mislead |

## Correlation principle

No single row should become an incident verdict by itself. Strong decisions join behavior, identity, asset importance, vulnerability state, intelligence quality, control health, and time.
