-- Accord VI accounts: Cloudflare D1 schema.
-- Apply locally:   npx wrangler d1 execute accord-accounts --local  --config wrangler.local.jsonc --file schema.sql
-- Apply in prod:   npx wrangler d1 execute accord-accounts --remote --file schema.sql   (after `wrangler d1 create`)

CREATE TABLE IF NOT EXISTS users (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  email             TEXT    NOT NULL UNIQUE COLLATE NOCASE,  -- UNIQUE is what makes duplicate sign-ups impossible
  name              TEXT    NOT NULL,
  pw_hash           TEXT    NOT NULL,                        -- v1$<iterations>$<salt>$<hash>, peppered PBKDF2-SHA256
  created_at        TEXT    NOT NULL,
  email_verified_at TEXT    NOT NULL,
  pw_changed_at     TEXT
);

-- Only a SHA-256 of the session token is stored, never the token itself, so a
-- leaked database cannot be replayed as live sessions.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT    PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- One ticket (registration) per account. The price is always worked out on the
-- server from the pass and headcount, never taken from the browser. The receipt
-- photo is stored here as a compressed data URL (the page shrinks it to roughly
-- 300 KB first), so no extra storage service is needed.
CREATE TABLE IF NOT EXISTS tickets (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  persona        TEXT    NOT NULL,                -- student | group | guest | sponsor
  hear_about     TEXT    NOT NULL DEFAULT '',
  attendee_count INTEGER NOT NULL DEFAULT 1,
  group_names    TEXT    NOT NULL DEFAULT '',
  sponsor_tier   TEXT    NOT NULL DEFAULT '',
  pass           TEXT    NOT NULL,                -- concert | both | sponsor
  amount_pkr     INTEGER NOT NULL,
  pay_method     TEXT    NOT NULL,                -- jazzcash | bank | cash | none
  receipt        TEXT,                            -- data:image/...;base64,... (null for cash and sponsors)
  status         TEXT    NOT NULL,                -- pending | confirmed | interest (sponsors)
  submitted_at   TEXT    NOT NULL,
  confirmed_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status, submitted_at);

-- Every receipt that gets replaced while a ticket is still pending is kept here,
-- so a re-upload never silently destroys the earlier one. Deleted with the account.
CREATE TABLE IF NOT EXISTS receipt_history (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_id    INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  receipt      TEXT    NOT NULL,
  pay_method   TEXT    NOT NULL,
  amount_pkr   INTEGER NOT NULL,
  submitted_at TEXT    NOT NULL,   -- when that receipt was first submitted
  replaced_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_receipt_history_ticket ON receipt_history(ticket_id);

-- One row per person who is allowed in: created when a payment is confirmed
-- (a group of 4 gets 4 rows). The QR code carries `id` plus a signature that only
-- the server can make (see TICKET_SECRET), and admitted_at is set the first time
-- someone is let in, so a copied ticket is refused the second time.
CREATE TABLE IF NOT EXISTS attendee_tickets (
  id          TEXT    PRIMARY KEY,                 -- random 96-bit id (base64url)
  ticket_id   INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  seq         INTEGER NOT NULL,                    -- 1..attendee_count
  holder_name TEXT    NOT NULL,
  created_at  TEXT    NOT NULL,
  admitted_at TEXT,
  UNIQUE (ticket_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_attendee_name ON attendee_tickets(holder_name COLLATE NOCASE);
