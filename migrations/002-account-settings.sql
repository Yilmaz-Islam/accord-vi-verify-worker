-- One-time upgrade for a database created BEFORE the account-settings features
-- (device list, sign-in alerts, avatar colour). Run it once on each existing database:
--   npx wrangler d1 execute accord-accounts --local  --config wrangler.local.jsonc --file migrations/002-account-settings.sql
--   npx wrangler d1 execute accord-accounts --remote --file migrations/002-account-settings.sql
-- A brand-new database does NOT need it: schema.sql already includes these columns.
-- (Running it twice fails with "duplicate column name", which is harmless.)

ALTER TABLE sessions ADD COLUMN user_agent TEXT;
ALTER TABLE sessions ADD COLUMN country    TEXT;
ALTER TABLE sessions ADD COLUMN last_seen  INTEGER;
ALTER TABLE users    ADD COLUMN login_alerts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users    ADD COLUMN avatar_color TEXT;

CREATE TABLE IF NOT EXISTS known_devices (
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_hash TEXT    NOT NULL,
  first_seen  TEXT    NOT NULL,
  PRIMARY KEY (user_id, device_hash)
);
