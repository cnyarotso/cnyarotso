# Data Dictionary

All records in the sample are synthetic.

| Field | Type | Validation | Purpose |
|---|---|---|---|
| `exposure_id` | String | Required and unique | Traceable record identifier |
| `asset_name` | String | Required | Fictional affected asset |
| `business_service` | String | Required | Business context for reporting |
| `cve` | String | Required | Vulnerability identifier |
| `cvss` | Decimal | 0–10 | Technical severity component |
| `asset_criticality` | Integer | 1–5 | Business/mission importance |
| `known_exploited` | Boolean | `true` or `false` | Known exploitation signal |
| `active_exploitation` | Boolean | `true` or `false` | Relevant current threat evidence |
| `externally_reachable` | Boolean | `true` or `false` | Exposure/reachability context |
| `identity_privileged` | Boolean | `true` or `false` | Privilege/blast-radius context |
| `control_coverage` | Integer | 0–100 | Preventive/detective control coverage |
| `days_open` | Integer | 0 or greater | Exposure age |
| `intelligence_confidence` | Enum | `low`, `moderate`, or `high` | Confidence in threat evidence |
| `owner` | String | Required | Remediation accountability |
| `status` | Enum | `open`, `in_progress`, `exception`, or `remediated` | Workflow state |

The script rejects missing, malformed, out-of-range, duplicate, or unsupported values instead of silently producing a misleading score.
