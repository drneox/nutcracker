-- Esquema SQLite de nutcracker (Fase 0.1 del plan: persistencia core).
-- Convenciones: timestamps en ISO-8601 UTC (texto), booleans como INTEGER 0/1.

CREATE TABLE IF NOT EXISTS apps (
    package         TEXT PRIMARY KEY,
    source          TEXT,               -- apkpure | google-play | local | url
    first_seen      TEXT NOT NULL,
    last_run_at     TEXT,
    next_due_at     TEXT,
    schedule_json   TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    package         TEXT NOT NULL REFERENCES apps(package) ON DELETE CASCADE,
    kind            TEXT NOT NULL DEFAULT 'full',     -- static | dynamic | full
    status          TEXT NOT NULL DEFAULT 'queued',   -- queued | running | done | error
    started_at      TEXT,
    finished_at     TEXT,
    verdict         TEXT,               -- protected | protection_broken | not_protected | ...
    masvs_score     INTEGER,
    grade           TEXT,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_package ON runs(package);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL,
    title           TEXT,
    severity        TEXT,               -- critical | high | medium | low | info
    category        TEXT,
    masvs           TEXT,               -- CSV de control ids, p.ej. "MASVS-STORAGE-1,MASVS-CRYPTO-1"
    maswe           TEXT,               -- CSV de MASWE ids
    cwe             TEXT,               -- CSV de CWE ids
    file            TEXT,
    line            INTEGER,
    confirmed       INTEGER             -- NULL=no evaluado, 1=confirmado (aireview), 0=falso positivo
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);

CREATE TABLE IF NOT EXISTS artifacts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    type            TEXT NOT NULL,      -- pdf | json | screenshot | frida_log
    path            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_run ON artifacts(run_id);

CREATE TABLE IF NOT EXISTS schedule (
    package             TEXT PRIMARY KEY REFERENCES apps(package) ON DELETE CASCADE,
    interval_days       INTEGER NOT NULL DEFAULT 30,
    cron                TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    last_scheduled_at   TEXT
);
