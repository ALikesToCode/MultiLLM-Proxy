CREATE TABLE IF NOT EXISTS tenant_governance_policies (
  org_id TEXT NOT NULL, team_id TEXT NOT NULL DEFAULT '', revision INTEGER NOT NULL DEFAULT 0,
  models TEXT, tools TEXT, daily INTEGER CHECK (daily IS NULL OR daily >= 0),
  monthly INTEGER CHECK (monthly IS NULL OR monthly >= 0), PRIMARY KEY (org_id, team_id)
);
CREATE TABLE IF NOT EXISTS tenant_governance_reservations (
  id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, org_id TEXT NOT NULL, team_id TEXT NOT NULL DEFAULT '',
  day TEXT NOT NULL, month TEXT NOT NULL, estimate INTEGER NOT NULL CHECK (estimate >= 0),
  charged INTEGER, state TEXT NOT NULL CHECK (state IN ('reserved','dispatched','unknown','settled')),
  revision INTEGER NOT NULL DEFAULT 0, provider TEXT, model TEXT, price_basis TEXT,
  created_at TEXT NOT NULL, operation_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tenant_governance_components (
  reservation_id TEXT NOT NULL REFERENCES tenant_governance_reservations(id),
  level TEXT NOT NULL, scope_org TEXT NOT NULL, scope_id TEXT NOT NULL,
  period_kind TEXT NOT NULL, period TEXT NOT NULL, limit_units INTEGER,
  PRIMARY KEY (reservation_id, level, scope_org, scope_id, period_kind)
);
CREATE INDEX IF NOT EXISTS tenant_governance_component_scope
  ON tenant_governance_components(level, scope_org, scope_id, period_kind, period);
CREATE INDEX IF NOT EXISTS tenant_governance_usage_scope
  ON tenant_governance_reservations(org_id, team_id, principal_id, day);
CREATE TABLE IF NOT EXISTS tenant_governance_baselines (
  principal_id TEXT NOT NULL, period TEXT NOT NULL, amount INTEGER NOT NULL,
  PRIMARY KEY (principal_id, period)
);
CREATE TABLE IF NOT EXISTS tenant_governance_audit (
  operation_id TEXT PRIMARY KEY, actor TEXT NOT NULL, org_id TEXT NOT NULL, team_id TEXT NOT NULL DEFAULT '',
  revision INTEGER NOT NULL, kind TEXT NOT NULL, at TEXT NOT NULL
);
