-- One-time upgrade for a database created BEFORE sign-up asked people to accept the
-- Terms and the Privacy Policy. Run it once on each existing database (after 002):
--   npx wrangler d1 execute accord-accounts --local  --config wrangler.local.jsonc --file migrations/003-terms-acceptance.sql
--   npx wrangler d1 execute accord-accounts --remote --file migrations/003-terms-acceptance.sql
-- A brand-new database does NOT need it: schema.sql already includes these columns.
-- (Running it twice fails with "duplicate column name", which is harmless.)
-- Accounts that already exist keep NULL: we never recorded their agreement, and we do not invent one.

ALTER TABLE users ADD COLUMN terms_accepted_at TEXT;
ALTER TABLE users ADD COLUMN terms_version     TEXT;
