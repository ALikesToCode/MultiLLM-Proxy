-- Keep the previous policy before adding the primary Claude candidate.
-- Existing code skips the new native provider until its transport is deployed.
INSERT OR IGNORE INTO shadow_eval_policy_backups (id, created_at, document)
SELECT 'haiku-primary-20261011', unixepoch(), document
FROM intelligence_policy
WHERE id = 1 AND CASE WHEN json_valid(document) THEN
  json_extract(document, '$.version') = 1
  AND json_extract(document, '$.enabled') = 1
  AND json_type(document, '$.candidates') = 'array'
  AND NOT EXISTS (
    SELECT 1 FROM json_each(document, '$.candidates')
    WHERE CASE WHEN type = 'object' THEN
      json_type(value, '$.model') IS NOT 'text'
    ELSE 1 END
  )
  AND (json_array_length(document, '$.candidates') < 64 OR EXISTS (
    SELECT 1 FROM json_each(document, '$.candidates')
    WHERE CASE WHEN type = 'object' THEN json_extract(value, '$.model') END
      = 'anthropic:claude-haiku-5-5'
  ))
ELSE 0 END;

UPDATE intelligence_policy
SET document = json_set(document,
  '$.allow_paid_overage', json('true'),
  '$.candidates', json((
    SELECT json_group_array(json(candidate)) FROM (
      SELECT COALESCE((
        SELECT value FROM json_each(intelligence_policy.document, '$.candidates')
        WHERE json_extract(value, '$.model') = 'anthropic:claude-haiku-5-5'
        LIMIT 1
      ), '{"model":"anthropic:claude-haiku-5-5","capabilities":["tools","json","streaming","reasoning"],"enabled":true,"entitled":true,"privacy_allowed":true,"billing":"payg","context_window":1000000,"max_output_tokens":128000,"quality_tier":1}')
        AS candidate, -1 AS priority
      UNION ALL
      SELECT value, CAST(key AS INTEGER)
      FROM json_each(intelligence_policy.document, '$.candidates')
      WHERE json_extract(value, '$.model') != 'anthropic:claude-haiku-5-5'
      ORDER BY priority
    )
  ))
)
WHERE id = 1 AND EXISTS (
  SELECT 1 FROM shadow_eval_policy_backups
  WHERE id = 'haiku-primary-20261011' AND document = intelligence_policy.document
);
