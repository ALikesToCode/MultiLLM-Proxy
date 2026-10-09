-- Optional two-level hierarchy; existing accounts and owned records are unchanged.
CREATE TABLE IF NOT EXISTS tenant_organisations (
    id TEXT PRIMARY KEY, name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'deactivated')),
    revision INTEGER NOT NULL CHECK (revision >= 1)
);
CREATE TABLE IF NOT EXISTS tenant_teams (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL, name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'deactivated')),
    revision INTEGER NOT NULL CHECK (revision >= 1)
);
CREATE INDEX IF NOT EXISTS tenant_teams_org ON tenant_teams (org_id, id);
CREATE TABLE IF NOT EXISTS tenant_memberships (
    org_id TEXT NOT NULL, principal TEXT NOT NULL, team_id TEXT,
    role TEXT NOT NULL CHECK (role IN ('admin', 'billing', 'member')),
    status TEXT NOT NULL CHECK (status IN ('active', 'deactivated')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    PRIMARY KEY (org_id, principal)
);
CREATE INDEX IF NOT EXISTS tenant_memberships_principal ON tenant_memberships (principal, org_id);
CREATE TABLE IF NOT EXISTS tenant_bindings (
    principal TEXT PRIMARY KEY, org_id TEXT NOT NULL, team_id TEXT,
    revision INTEGER NOT NULL CHECK (revision >= 1)
);
CREATE TABLE IF NOT EXISTS tenant_audit (
    id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
    org_id TEXT, team_id TEXT, principal TEXT,
    old_revision INTEGER NOT NULL, new_revision INTEGER NOT NULL, at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS tenant_audit_time ON tenant_audit (at, id);
