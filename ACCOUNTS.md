# Accounts, tickets, payment confirmation and the gate

Sign-up, login, event registration with a receipt upload, admin payment confirmation,
per-person QR tickets and a gate scanner, all in the `accord-vi-verify` worker.
Code is in `src/accounts.js`, the database in `schema.sql`.

## The flow

1. Anyone can browse the whole site. **Register** asks for an account first (a popup with a Sign up button).
2. Signing up emails a 6-digit code once; after that the register wizard already knows the name and email.
3. The wizard collects who they are, the pass (Concert only Rs 2,500, Both nights Rs 3,500, times the group size),
   and how they pay. JazzCash and bank transfer need a clear receipt photo. Cash does not. Sponsors register interest only.
4. Submitting saves a **pending** registration and sends a "pending payment verification" email to the person and a notice
   to the organisers. **One registration per account**: they can replace a pending one (for example to upload a clearer
   receipt) but every replaced receipt is archived in `receipt_history`, so nothing is lost. A confirmed one is locked.
5. An admin opens the Tickets tab, views the receipt next to the name, email and amount (and any earlier receipts), and
   presses **Payment confirmed**. That marks it confirmed, **creates one ticket per person**, and emails the buyer a
   confirmation with a link and button for each ticket. The row moves from Pending to Confirmed in the admin lists.
6. Each ticket is a QR code. A group of 4 gets 4 tickets, named from the list the leader typed ("Guest 3 (Name's group)" if blank).
7. At the gate, staff sign in to the **gate scanner** with the gate password, scan the QR (or search by name), see the name
   and pass, ask the guest "what name is the ticket under?", check ID, then tap **Admit**. Admit marks the ticket used; a
   second scan of the same ticket shows "Already used". Only the Admit tap uses a ticket, never the scan alone.
8. Deleting an account (not possible once a payment is confirmed) emails the person, then erases the account, registration,
   receipts, receipt history, tickets and the older-style log entries for that email.

### How tickets cannot be forged or reused
A ticket code is `A6.<random id>.<signature>`. The signature is an HMAC made with the secret `TICKET_SECRET`, which only the
server has, so nobody (including an AI) can invent a code that passes. The server also records the first admit, so a copied
or screenshotted ticket works at most once. A QR code *can* be photographed and shared, so the real protections are the
single use and the name/ID check at the gate. The gate staff's own password (`GATE_PASSWORD`) lets them scan and admit only:
they cannot see receipts or registration lists.

## Run and test locally

```bash
npm install
npx wrangler d1 execute accord-accounts --local --config wrangler.local.jsonc --file schema.sql
npx wrangler dev --config wrangler.local.jsonc --port 8787
node test-accounts.mjs      # 32 checks: sign-up, login, sessions, reset, delete, deletion email
node test-tickets.mjs       # 29 checks: pricing, receipts, admin review, confirmation, email safety
node test-gate.mjs          # 44 checks: tickets, forged codes, gate access, one-time admit, receipt history
```

Local runs use a simulated D1 and KV. `.dev.vars` (git-ignored) holds `PEPPER`, `ADMIN_PASSWORD`, `TICKET_SECRET` and
`GATE_PASSWORD` for local testing; restart `wrangler dev` after changing it. `DEV_MODE=1` in `wrangler.local.jsonc` returns
email codes in the response and keeps outgoing emails in `/dev/outbox`. **Never put `DEV_MODE` in `wrangler.jsonc`.**

## Routes (all POST, JSON)

| Route | Body | Auth | Result |
| --- | --- | --- | --- |
| `/account/signup/request` | name, email, password | none | emails a 6-digit code |
| `/account/signup/verify` | email, code | none | creates the account, returns `token` and `user` |
| `/account/login` | email, password | none | `token` and `user` |
| `/account/logout` | - | Bearer | deletes this session |
| `/account/me` | - | Bearer | `user` and `ticket` (the registration, or null) |
| `/account/update` | name | Bearer | updates the profile |
| `/account/ticket/submit` | persona, pass, payMethod, receipt, ... | Bearer | saves a pending registration, archives a replaced receipt, sends the emails |
| `/account/tickets` | - | Bearer | the person's QR tickets (only after the payment is confirmed) |
| `/account/password/forgot` / `reset` | email / email, code, newPassword | none | emailed code, then new password; signs out every device |
| `/account/delete` | password | Bearer | deletes everything about them and emails them (refused once a payment is confirmed) |
| `/admin/tickets` | - | admin | every registration, without images |
| `/admin/ticket-receipt` / `ticket-history` | id | admin | the current receipt / the replaced ones |
| `/admin/ticket-confirm` | id | admin | confirms, creates the tickets, emails the buyer |
| `/ticket/info` | code | none (needs a genuine code) | what a ticket page shows: holder, pass, used or not |
| `/gate/login` | password | none | a gate token (12 hours) |
| `/gate/lookup` / `search` / `admit` | code or q or id | gate or admin | show a ticket / find by name / admit (once) |

## EmailJS: one template for every email to a person

The free plan allows two templates; one notifies the organisers (`EMAILJS_NOTIFY_TEMPLATE_ID`). The other
(`EMAILJS_CODE_TEMPLATE_ID`) carries every email to a person. It is set to: Subject `{{subject}}`, Content `{{{html}}}`
(triple braces = real HTML), To `{{email}}`, From Name "Accord VI", Reply To the organiser inbox. The worker writes the text
and a branded HTML card (with buttons) for each email and also sends a plain `message` for clients without HTML.
Each registration uses about 3 EmailJS requests (sign-up code, pending, confirmed); the free plan has 200 a month.

Optional `vars`: `SITE_NAME` (default "Accord VI") and `SITE_URL` (default `https://yilmaz-islam.github.io/accord-vi`).

## Secrets (set with `npx wrangler secret put <NAME>`)

| Secret | What it does | If it is lost or changed |
| --- | --- | --- |
| `PEPPER` | scrambles passwords | every password stops working |
| `TICKET_SECRET` | signs the QR tickets | every issued ticket stops being valid |
| `GATE_PASSWORD` | door staff sign-in | harmless: set a new one |
| `ADMIN_PASSWORD` | admin sign-in | harmless: set a new one |

Keep a copy of `PEPPER` and `TICKET_SECRET` somewhere safe. Never commit any of them.

## Deploying changes

1. `npx wrangler d1 execute accord-accounts --remote --file schema.sql` (safe to repeat: every statement is `IF NOT EXISTS`).
2. Set any new secret (see the table).
3. `npx wrangler deploy`
4. Push the site pages (this redeploys the live site).
5. Test one registration end to end.

## Backups

`scripts/backup-accord.ps1` exports the whole database (receipt images included) and the older KV log to
`C:\Users\HP\accord-backups\<date>`, outside OneDrive, and deletes backups older than 30 days (this is also how deleted
people's data leaves the backups). `scripts/install-backup-task.ps1` schedules it daily at 03:00 as a Windows task; it
catches up after the laptop was off. Check `backup.log` in that folder. To restore into an empty database:
`npx wrangler d1 execute accord-accounts --remote --file <folder>\accord-accounts.sql`.
Backups hold personal details and receipts: keep them off shared drives. Cloudflare D1 also keeps its own recent history
(Time Travel), which is a second safety net but not a substitute for these.

## Security notes

- Passwords: HMAC with the secret `PEPPER`, then PBKDF2-SHA256 at 100,000 iterations (the most Workers allows; OWASP
  recommends 600,000, so the pepper, the 10-character minimum and the rate limits make up the gap).
- Sessions: random 256-bit token; only its SHA-256 is stored; 7-day expiry; logout and password reset delete sessions.
- No account enumeration: sign-up and forgot-password answer the same whether or not the email exists; login has one generic error.
- Rate limits (KV counters): sign-up, login, reset, ticket submission, account deletion, gate login, ticket info.
- The admin panel is reached only via the hidden (c) on the Terms page, which leaves a 30-minute pass that `admin.html`
  checks. This hides the panel; it is not security. The admin password and its rate limit are what protect it.
- Tokens live in `localStorage`. Robust to third-party-cookie blocking, but any XSS bug on the site could steal one.
- Receipts are personal financial documents. They are returned only to the admin token.
- HTML emails escape everything a person typed (for example a name), and button links are fixed by the server.
