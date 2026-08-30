BEGIN;
CREATE TABLE IF NOT EXISTS sentrycode_schema_migrations(version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS sentrycode_repositories(
 id text PRIMARY KEY, tenant text NOT NULL, project text NOT NULL, name text NOT NULL, root_path text NOT NULL,
 default_branch text NOT NULL DEFAULT 'main', enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant, project, name)
);
CREATE INDEX IF NOT EXISTS sentrycode_repositories_scope_idx ON sentrycode_repositories(tenant, project);
CREATE TABLE IF NOT EXISTS sentrycode_scanner_settings(
 repository_id text NOT NULL REFERENCES sentrycode_repositories(id) ON DELETE CASCADE, scanner text NOT NULL,
 enabled boolean NOT NULL, required boolean NOT NULL, failure_mode text NOT NULL CHECK(failure_mode IN ('fail','warn','ignore')),
 updated_at timestamptz NOT NULL DEFAULT now(), updated_by text NOT NULL, PRIMARY KEY(repository_id, scanner)
);
CREATE TABLE IF NOT EXISTS sentrycode_policy_assignments(
 id text PRIMARY KEY, tenant text NOT NULL, project text NOT NULL, repository_id text NULL REFERENCES sentrycode_repositories(id) ON DELETE CASCADE,
 service text NULL, fail_on jsonb NOT NULL DEFAULT '[]', warn_on jsonb NOT NULL DEFAULT '[]', required_scanners jsonb NOT NULL DEFAULT '[]',
 scanner_failure_modes jsonb NOT NULL DEFAULT '{}', locked_fields jsonb NOT NULL DEFAULT '[]', version integer NOT NULL DEFAULT 1,
 updated_at timestamptz NOT NULL DEFAULT now(), updated_by text NOT NULL
);
CREATE INDEX IF NOT EXISTS sentrycode_policy_scope_idx ON sentrycode_policy_assignments(tenant, project);
CREATE TABLE IF NOT EXISTS sentrycode_waiver_workflow(
 id text PRIMARY KEY, tenant text NOT NULL, project text NOT NULL, repository_id text NULL REFERENCES sentrycode_repositories(id) ON DELETE SET NULL,
 finding_id text NULL, rule_id text NULL, scanner text NULL, path text NULL, fingerprint text NULL,
 reason text NOT NULL, ticket text NULL, author text NOT NULL, approver text NULL,
 status text NOT NULL CHECK(status IN ('pending','active','rejected','revoked','expired')),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, decided_at timestamptz NULL
);
CREATE INDEX IF NOT EXISTS sentrycode_waiver_scope_idx ON sentrycode_waiver_workflow(tenant, project, status);
CREATE TABLE IF NOT EXISTS sentrycode_integrations(
 id text PRIMARY KEY, tenant text NOT NULL, project text NOT NULL, kind text NOT NULL, name text NOT NULL, enabled boolean NOT NULL DEFAULT true,
 configuration jsonb NOT NULL DEFAULT '{}', secret_reference text NULL,
 status text NOT NULL CHECK(status IN ('configured','connected','error','not_configured')),
 updated_at timestamptz NOT NULL DEFAULT now(), updated_by text NOT NULL
);
CREATE TABLE IF NOT EXISTS sentrycode_principals(
 id text PRIMARY KEY, subject text NOT NULL UNIQUE, display_name text NOT NULL,
 role text NOT NULL CHECK(role IN ('viewer','engineer','security_admin','administrator')), enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sentrycode_application_audit(
 id text PRIMARY KEY, at timestamptz NOT NULL, actor text NOT NULL, action text NOT NULL,
 entity_type text NOT NULL, entity_id text NOT NULL, detail jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS sentrycode_application_audit_at_idx ON sentrycode_application_audit(at DESC);
INSERT INTO sentrycode_schema_migrations(version) VALUES (1) ON CONFLICT(version) DO NOTHING;
COMMIT;
