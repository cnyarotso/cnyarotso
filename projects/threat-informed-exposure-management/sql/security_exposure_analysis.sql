-- name: urgent_action_queue
-- Critical or high open exposures with exploitation or reachability evidence.
SELECT
    exposure_id,
    business_service,
    owner,
    priority_band,
    priority_score,
    days_open,
    remediation_sla_days,
    sla_breached
FROM exposures
WHERE status <> 'remediated'
  AND priority_band IN ('Critical', 'High')
  AND (known_exploited = 1 OR active_exploitation = 1 OR externally_reachable = 1)
ORDER BY priority_score DESC, days_open DESC;

-- name: overdue_by_owner
-- Workload and risk concentration for exposures that have exceeded their SLA.
SELECT
    owner,
    COUNT(*) AS overdue_exposures,
    ROUND(AVG(priority_score), 1) AS average_priority_score,
    MAX(days_open) AS oldest_days_open
FROM exposures
WHERE sla_breached = 1
  AND status <> 'remediated'
GROUP BY owner
ORDER BY overdue_exposures DESC, average_priority_score DESC;

-- name: top_exposure_per_service
-- Window function keeps the full row while selecting each service's top exposure.
WITH ranked AS (
    SELECT
        exposure_id,
        business_service,
        owner,
        priority_band,
        priority_score,
        ROW_NUMBER() OVER (
            PARTITION BY business_service
            ORDER BY priority_score DESC, exposure_id
        ) AS service_rank
    FROM exposures
    WHERE status <> 'remediated'
)
SELECT
    exposure_id,
    business_service,
    owner,
    priority_band,
    priority_score
FROM ranked
WHERE service_rank = 1
ORDER BY priority_score DESC;

-- name: duplicate_identifier_check
-- A data-quality control that should return no rows for a valid data set.
SELECT
    exposure_id,
    COUNT(*) AS record_count
FROM exposures
GROUP BY exposure_id
HAVING COUNT(*) > 1;
