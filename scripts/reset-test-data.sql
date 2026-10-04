-- Erases every account, registration, receipt and ticket so the whole flow can be tested from nothing.
-- Keeps the tables, the indexes and the secrets. Does not touch the older registration log (that lives in KV).
-- Children first, so nothing depends on a row that is already gone.
DELETE FROM attendee_tickets;
DELETE FROM receipt_history;
DELETE FROM tickets;
DELETE FROM known_devices;
DELETE FROM sessions;
DELETE FROM users;
