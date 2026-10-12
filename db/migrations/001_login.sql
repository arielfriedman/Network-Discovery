-- 001: login system - the six tables from docs/POSTGRES_ROADMAP.md Part 1,
-- plus the optional columns marked there and a login_attempts table.

CREATE TABLE users (
    id            int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name          varchar(100) NOT NULL,
    email         varchar(255) NOT NULL UNIQUE,
    password_hash varchar(255) NOT NULL,          -- scrypt hash, never the password; '!' = cannot log in
    created_at    timestamptz  NOT NULL DEFAULT now(),
    is_active     boolean      NOT NULL DEFAULT true,   -- deactivate instead of delete
    last_login_at timestamptz
);

CREATE TABLE roles (
    id   int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name varchar(50) NOT NULL UNIQUE
);

CREATE TABLE permissions (
    id   int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name varchar(50) NOT NULL UNIQUE
);

CREATE TABLE user_roles (
    user_id int NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id int NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE role_permissions (
    role_id       int NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id int NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_activity (
    id         int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    int         NOT NULL REFERENCES users(id),
    action     varchar(50) NOT NULL,              -- scan.start, device.config.apply, ...
    created_at timestamptz NOT NULL DEFAULT now(),
    target     text,                              -- scan id, device IP, ...
    source_ip  inet,
    details    jsonb
);
CREATE INDEX ON user_activity (user_id, created_at DESC);
CREATE INDEX ON user_activity (created_at DESC);

-- The activity log is append-only, whoever is connected.
CREATE FUNCTION forbid_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;
CREATE TRIGGER user_activity_append_only
    BEFORE UPDATE OR DELETE ON user_activity
    FOR EACH ROW EXECUTE FUNCTION forbid_change();

-- Failed logins for unknown emails cannot reference users(id), so they live here.
CREATE TABLE login_attempts (
    id         int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email      varchar(255) NOT NULL,
    source_ip  inet,
    success    boolean     NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Starting data (roadmap "Suggested starting data")
INSERT INTO roles (name) VALUES ('admin'), ('operator'), ('viewer');
INSERT INTO permissions (name) VALUES
    ('results.view'), ('results.export'), ('scan.run'), ('scan.stop'),
    ('device.view'), ('device.configure'), ('config.backup'), ('user.manage');
INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id FROM roles r CROSS JOIN permissions p WHERE r.name = 'admin';
INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name IN
        ('results.view', 'results.export', 'scan.run', 'scan.stop',
         'device.view', 'device.configure', 'config.backup')
    WHERE r.name = 'operator';
INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name IN ('results.view', 'device.view')
    WHERE r.name = 'viewer';

-- Until the panel has a login page, actions are recorded against this
-- built-in account. Its password hash '!' matches no password, so nobody can log in as it.
INSERT INTO users (name, email, password_hash) VALUES ('Local panel', 'local@localhost', '!');
INSERT INTO user_roles (user_id, role_id)
    SELECT u.id, r.id FROM users u, roles r WHERE u.email = 'local@localhost' AND r.name = 'admin';
