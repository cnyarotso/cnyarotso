# Historical Exposure Analytics

This extension replaces a one-time vulnerability snapshot with dated, synthetic observations. It demonstrates how an analyst can measure whether remediation work actually reduces exposure over time.

## Questions answered

- How long did each exposure take to reach a remediated state?
- Which exposures reopened after remediation?
- Which exposures recur across multiple scans?
- Which risk exceptions require review within 30 days?

## Evidence and controls

- `data/exposure_history.csv` contains fictional scan history and review dates.
- `src/analyze_exposure_history.py` loads the history into an in-memory SQLite database and runs four auditable queries.
- The compound primary key prevents two states for the same exposure in one snapshot.
- Invalid workflow states and duplicate snapshot records fail closed.
- `tests/test_analyze_exposure_history.py` validates expected remediation, recurrence, reopen, and exception results.

## Run

```bash
python src/analyze_exposure_history.py data/exposure_history.csv
python -m unittest discover -s tests -v
```

## Analyst interpretation

`EXP-002` was marked remediated and later returned to an open state. That is a reopened exposure requiring validation of the original fix, ownership, and recurrence cause—not simply another item in a static queue. `EXP-003` remains under exception and reaches its review date within 30 days of the latest snapshot, making it a governance priority.

## Production next step

Replace synthetic snapshots with scanner and asset-inventory extracts, preserve immutable remediation events, and calibrate SLA metrics with security and business owners.
