-- 010: Actions page (docs/ACTIONS_PLAN.md) - saved command buttons and their runs.

CREATE TABLE action_folders (
    id        int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name      text NOT NULL UNIQUE,
    position  int  NOT NULL DEFAULT 0
);

CREATE TABLE actions (
    id            int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    folder_id     int REFERENCES action_folders(id) ON DELETE SET NULL,
    name          text        NOT NULL,
    description   text,
    dangerous     boolean     NOT NULL DEFAULT false,   -- asks for an extra confirmation
    stop_on_error boolean     NOT NULL DEFAULT true,
    builtin_key   text UNIQUE,                         -- starter library entry; NULL = made by the user
    hidden        boolean     NOT NULL DEFAULT false,  -- a deleted starter action (so it isn't re-added)
    position      int         NOT NULL DEFAULT 0,
    created_by    int REFERENCES users(id),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- One row per step. command is the generic form; variants holds the
-- per-distro-family form ({"debian": "...", "rhel": "...", ...}) when it differs.
CREATE TABLE action_steps (
    action_id int  NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    position  int  NOT NULL,
    command   text NOT NULL,
    variants  jsonb,
    PRIMARY KEY (action_id, position)
);

CREATE TABLE action_runs (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action_id    int REFERENCES actions(id) ON DELETE SET NULL,
    action_name  text        NOT NULL,              -- kept if the action is deleted later
    target       text        NOT NULL DEFAULT 'this machine',
    distro       text,
    status       varchar(12) NOT NULL CHECK (status IN ('running', 'ok', 'failed', 'stopped', 'interrupted')),
    started_by   int REFERENCES users(id),
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz
);

CREATE TABLE action_run_steps (
    run_id     bigint NOT NULL REFERENCES action_runs(id) ON DELETE CASCADE,
    position   int    NOT NULL,
    command    text   NOT NULL,                     -- exactly what ran
    exit_code  int,
    duration_s numeric(10,1),
    output     text,                                -- last 256 KB
    PRIMARY KEY (run_id, position)
);
CREATE INDEX action_runs_started ON action_runs (started_at DESC);
