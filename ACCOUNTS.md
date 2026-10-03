# Accounts, tickets and payment confirmation

Sign-up, login, event registration with a receipt upload, and admin payment
confirmation, added to the existing `accord-vi-verify` worker. Code is in
`src/accounts.js`, the database in `schema.sql`. **Nothing here is deployed yet.**

## The flow

1. Anyone can browse the whole site. **Register** asks for an account first (a popup with a Sign up button).
2. Signing up emails a 6-digit code once; after that the register wizard already knows the name and email.
3. The wizard collects who they are, the pass (Concert only Rs 2,500, Both nights Rs 3,500, times the group size), and how they pay.
   JazzCash and bank transfer need a receipt photo. Cash does not. Sponsors only register interest (no payment).
4. Submitting saves a **pending** ticket and sends a "pending payment verification" email to the person and a notice to the organisers.
5. An admin opens the Tickets tab, views the receipt next to the name, email and amount, and presses **Payment confirmed**.
   That marks the ticket confirmed and sends the "payment confirmed" email. Pressing twice never sends two emails.

The price is always worked out on the server. The receipt is shrunk in the browser to about 300 KB and stored in D1.

## Run and test locally

```bash
npm install
npx wrangler d1 execute accord-accounts --local --config wrangler.local.jsonc --file schema.sql
npx wrangler dev --config wrangler.local.jsonc --port 8787
node test-accounts.mjs      # in a second terminal: 31 checks (sign-up, login, sessions, reset, delete)
node test-tickets.mjs       # 27 checks (pricing, receipts, admin review, confirmation, emails)
```

Local runs use a simulated D1 and KV. `DEV_MODE=1` in `wrangler.local.jsonc` returns email codes in the response and
keeps outgoing emails in `/dev/outbox` instead of sending them. **Never put `DEV_MODE` in `wrangler.jsonc`.**

## Routes (all POST, JSON)

| Route | Body | Auth | Result |
| --- | --- | --- | --- |
| `/account/signup/request` | name, email, password | none | emails a 6-digit code |
| `/account/signup/verify` | email, code | none | creates the account, returns `token` and `user` |
| `/account/login` | email, password | none | `token` and `user` |
| `/account/logout` | - | Bearer | deletes this session |
| `/account/me` | - | Bearer | `user` and `ticket` (or null) |
| `/account/update` | name | Bearer | updates the profile |
| `/account/ticket/submit` | persona, pass, payMethod, receipt, ... | Bearer | saves a pending ticket, sends the emails |
| `/account/password/forgot` | email | none | always `ok`; emails a code if the account exists |
| `/account/password/reset` | email, code, newPassword | none | sets the password, signs out every device |
| `/account/delete` | password | Bearer | deletes the account (refused once a payment is confirmed) |
| `/admin/tickets` | - | admin | every ticket, without receipt images |
| `/admin/ticket-receipt` | id | admin | the receipt image |
| `/admin/ticket-confirm` | id | admin | confirms the payment and emails the person |

User routes send `Authorization: Bearer <token>`; admin routes use the existing admin token from `/admin/login`.

## EmailJS: one template for every email to a person

The free EmailJS plan allows only two templates. One already notifies the organisers
(`EMAILJS_NOTIFY_TEMPLATE_ID`). The other (`EMAILJS_CODE_TEMPLATE_ID`) must now carry **every** email to a person:
verification codes, "pending verification" and "payment confirmed". The worker writes the text; the template only displays it.

In EmailJS, edit the code template to:

- **Subject:** `{{subject}}`
- **Content:** `{{message}}`
- **To email:** `{{email}}`

The worker also sends `name`, `form_type` and `code`, so the old template keeps working until you switch it, but the
pending and confirmed emails will look wrong until you do. Free plan limits are small (I believe 200 emails a month);
each registration uses about three (sign-up code, pending, confirmed), so this will run out quickly at scale. You said
you may upgrade later. Brevo or a paid EmailJS plan are the fixes.

Optional variables in `wrangler.jsonc` `vars`: `SITE_NAME` (default "Accord VI", used in every email) and `SITE_URL`
(default `https://yilmaz-islam.github.io/accord-vi`). Changing the site name is a one-line change here plus the pages.

## Deploy checklist (your decision, in order)

1. `npx wrangler d1 create accord-accounts`, then copy the printed `database_id`.
2. Add to `wrangler.jsonc`:
   ```jsonc
   "d1_databases": [
     { "binding": "DB", "database_name": "accord-accounts", "database_id": "<id from step 1>" }
   ]
   ```
3. `npx wrangler d1 execute accord-accounts --remote --file schema.sql`
4. `npx wrangler secret put PEPPER` and paste a long random value
   (`node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`). Keep a copy somewhere safe.
   **If it is lost or changed, every password stops working.**
5. Update the EmailJS code template as above.
6. `npx wrangler deploy`
7. Push the site pages (this redeploys the live site) only after checking the preview.
8. Test one real sign-up, one registration and one confirmation. If anything fails with Cloudflare error 1102
   ("exceeded CPU"), the free plan's 10 ms CPU limit is too small for password hashing and the Workers Paid plan
   ($5/month) is needed.

## Security notes

- Passwords: HMAC with the secret `PEPPER`, then PBKDF2-SHA256 at 100,000 iterations (the most Workers allows;
  OWASP recommends 600,000, so the pepper, the 10-character minimum and the rate limits make up the gap).
- Sessions: random 256-bit token; only its SHA-256 is stored; 7-day expiry; logout and password reset delete sessions.
- No account enumeration: sign-up and forgot-password answer the same whether or not the email exists; login has one generic error.
- Rate limits (KV counters): sign-up, login (per IP and per email), reset, ticket submission, account deletion.
- The admin panel is reached only via the hidden (c) on the Terms page, which leaves a 30-minute pass that `admin.html`
  checks. This hides the panel; it is not security. The admin password and its rate limit are what protect it.
- Tokens live in `localStorage`, like the admin page. Robust to third-party-cookie blocking, but any XSS bug on the site
  could steal one.
- Receipts are personal financial documents. They are returned only to the admin token and deleted if the account is
  deleted (which is blocked once a payment is confirmed).
- Update `privacy-policy.html` before launch: it must say accounts store name, email, a password hash and payment
  receipts, who can see them, and how long they are kept.
