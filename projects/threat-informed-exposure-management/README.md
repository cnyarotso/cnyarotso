# Threat-Informed Exposure Prioritization Engine

> A transparent Python model that ranks synthetic vulnerability exposures using threat evidence, asset context, control coverage, age, ownership, and remediation SLAs—not CVSS alone.

## Objective and executive snapshot

| Area | Detail |
|---|---|
| Decision | Which exposures should be investigated or remediated first? |
| Analyst role | Define a data contract, implement explainable scoring, generate ranked output, and test expected behavior |
| Inputs | Synthetic vulnerability, exploitation, intelligence, asset, reachability, privilege, control, age, owner, and status fields |
| Output | Priority score/band, SLA, SLA-breach flag, reasons, and recommended action |
| Safety | All assets and exposure records are fictional |
| Limitation | The model supports prioritization; it does not replace analyst judgment or a production risk methodology |

## Problem statement

A high CVSS score does not automatically represent the most urgent business exposure. A lower-severity issue may deserve earlier action when exploitation is active, the asset is externally reachable or privileged, controls are weak, and the affected service is critical.

This project makes that reasoning visible and testable.

## Architecture and data flow

```mermaid
flowchart TD
    A["Synthetic exposure CSV"] --> B["Python validation and scoring"]
    B --> C["Ranked exposure CSV"]
    C --> D["In-memory SQLite model"]
    D --> E["Named analyst queries"]
    E --> F["Action queues and controls"]
```

The pipeline fails before writing output when required values, types, ranges, or unique identifiers are invalid. The committed ranked CSV is a reproducible sample result; a fresh run is compared with it during validation.

## Data model

The grain is one exposure on one fictional asset, identified by the primary key `exposure_id`. Each record combines:

- vulnerability severity and identifier;
- threat evidence and intelligence confidence;
- asset criticality, reachability, privilege, and control coverage;
- remediation owner, workflow status, age, priority, SLA, and recommended action.

The [data dictionary](docs/data_dictionary.md) defines every field and validation rule. Production data would separate assets, vulnerabilities, observations, threat intelligence, controls, owners, exceptions, and remediation events into related tables so history and many-to-many relationships remain auditable.

## Scoring model

| Factor | Maximum points |
|---|---:|
| CVSS severity | 15 |
| Asset criticality | 15 |
| Known exploited vulnerability | 20 |
| Active exploitation intelligence | 15 |
| External reachability | 10 |
| Privileged identity/system | 5 |
| Missing control coverage | 10 |
| Exposure age | 5 |
| Intelligence confidence | 5 |
| **Total** | **100** |

The full rationale, assumptions, and governance cautions are in the [methodology](docs/methodology.md).

## Run the project

Requirements: Python 3.10 or later; no third-party packages. SQLite is accessed through Python's standard library.

```bash
python src/prioritize_exposures.py data/sample_exposures.csv output/prioritized_exposures.csv
python src/run_sql_analysis.py output/prioritized_exposures.csv sql/security_exposure_analysis.sql
python -m unittest discover -s tests -v
```

## SQL analysis

The [named SQLite queries](sql/security_exposure_analysis.sql) turn the Python output into four analyst views:

- an urgent action queue for critical and high exposures with threat or reachability evidence;
- overdue exposure counts and aging by remediation owner;
- the highest-priority open exposure within each business service using a window function; and
- a duplicate-identifier control that should return no rows.

The Python runner uses an in-memory database, explicit data types, `NOT NULL` rules, range checks, and a primary key. No database file or sensitive data is created.

## Output fields

The ranked [sample output](output/prioritized_exposures.csv) adds:

- `priority_score`
- `priority_band`
- `remediation_sla_days`
- `sla_breached`
- `score_reasons`
- `recommended_action`

See the [data dictionary](docs/data_dictionary.md) for input validation rules.

## Analyst interpretation

The highest-ranked record should not be described merely as “the highest CVSS.” Its priority is explainable through the combination of exploitation evidence, critical asset context, reachability, weak controls, privilege, and age. A remediated record remains visible until closure is validated.

## Metrics for a dashboard

- Critical/high exposures by business service and owner
- Known-exploited or actively exploited exposures
- Externally reachable exposures with weak control coverage
- SLA breaches and exposure age
- Exceptions approaching review date
- Remediated items awaiting validation

## Limitations

- The weights are a documented demonstration model, not an organizational risk standard.
- Inputs are synthetic and do not represent Regions Bank or any real company.
- The model assumes trustworthy scanner, CMDB, control, and intelligence data.
- Business owners must review exceptions and remediation feasibility.
- Production deployment requires calibration, access controls, audit history, and monitoring.

## Design choices and lessons

- **Transparent rules instead of a black box:** reviewers can trace every score to documented factors and see the reasons in the output.
- **Fail closed on invalid data:** malformed booleans, missing fields, duplicate identifiers, out-of-range numbers, and fractional values in integer fields stop processing instead of producing misleading priorities.
- **Bug corrected:** the first implementation converted validated numeric values with `int()`, which could silently truncate a value such as `3.9`. A dedicated integer parser now rejects fractional inputs, and a regression test preserves the fix.
- **Historical analytics added:** dated scan snapshots and exception-review dates now support recurrence, time-to-remediation, reopened-exposure, and expiring-exception analysis.

## Connection to cybersecurity analyst work

This project demonstrates CTI-to-exposure correlation, risk-based remediation prioritization, transparent automation, SLA reporting, quality validation, and concise communication to technical and leadership audiences.


## Historical remediation analytics

The [historical analytics extension](docs/historical_analytics.md) adds dated synthetic scan snapshots, exception-review dates, four SQLite analyses, and automated tests. It measures time to remediation, recurring exposure, reopened items, and exceptions due for review—moving the project from a static priority list to a remediation-performance workflow.
