-- Synthetic v0.15.0-shape schema seed.
--
-- *** This is NOT a real production dump. *** It is a minimal, hand-rolled
-- subset of the schema as it stood at chainsaw 0.15.x — just enough tables
-- and columns to give pgstore.migrate() a "different starting state" than
-- an empty database, and to prove the no-migration-runner thesis: idempotent
-- DDL can move a stale schema forward without an external runner.
--
-- The thesis being tested (docs/MIGRATIONS.md):
--
--   "Until non-idempotent operations (ALTER TABLE on existing rows, data
--    backfills, rollbacks) become unavoidable, pgstore.migrate() is both
--    the schema and the release record."
--
-- What this seed deliberately includes:
--   - The core tenancy and audit tables that existed at 0.15.x
--     (orgs, users, memberships, settings, repositories, events).
--   - Just enough columns to exercise additive ALTER TABLE paths in
--     migrate() (e.g. webhooks WITHOUT secret_ciphertext).
--
-- What it deliberately leaves out (so migrate() must add them):
--   - sbom_snapshots, team_webhook_destinations, ownership_glob_rules,
--     exception_reminders_sent, exception_expiry_banners, risk_weight_overrides
--     (all [Unreleased] / 0.16.0 effectiveness-uplift tables)
--   - findings, policy_versions (post-0.16.0 audit additions)
--   - schema_version (0.16.0 doctor probe)
--
-- When N+1 ships and adds new tables / columns, copy this file to
-- testdata/v<N>_schema.sql, drop the relevant additions, and add a new
-- TestMigrate_FromV<N>Schema in upgrade_path_test.go. See the
-- "Upgrade-path CI test" section in docs/MIGRATIONS.md for the recipe.

-- Wipe everything the test session can see so we start from a known floor.
-- DROP SCHEMA + CREATE keeps the test idempotent across reruns against
-- the same Postgres instance (CI service container reuses the database).
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;

-- Core tenancy.
CREATE TABLE orgs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ
);

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    password_hash TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE memberships (
    org_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE settings (
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    org_id TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (org_id, key)
);

-- A subset of the proxy data plane: enough to seed a couple of rows
-- and confirm post-migrate() reads still see them.
CREATE TABLE repositories (
    org_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    format TEXT NOT NULL,
    type TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    anonymous_access INTEGER NOT NULL DEFAULT 0,
    remote_url TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (org_id, name)
);

-- Webhooks at 0.15.x had no secret_ciphertext column — migrate() should
-- add it via the addColumnIfMissing path. We seed a row to prove the
-- additive ALTER TABLE doesn't trash existing data.
CREATE TABLE webhooks (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    user_id TEXT,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- A pre-existing webhook row so we can assert it survives the upgrade.
INSERT INTO webhooks (id, org_id, url, secret)
    VALUES ('wh-pre-upgrade', 'default', 'https://example.invalid/hook', 'legacy-plaintext-secret');
