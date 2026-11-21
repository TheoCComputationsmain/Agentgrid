# External payments and billing workflow

AgentGrid does **not** move money. There is no wallet, balance, escrow, auto
top-up, in-app checkout, server-side payment key, automatic deduction, or payment
webhook. All money changes hands outside the platform; the service only records
references to external payments after the operator confirms them. Customers
register with an email and use that same email on the Cashfree form, so a
mistyped Client ID can be corrected automatically without operator help.

## Tiers and prices

| Tier | Base | Included agents | Included handoffs / cycle |
|---|---:|---:|---:|
| Free | $0 | 5 | 100 |
| Plus | $20 | 100 | 10,000 |
| Pro | $150 | 1,000 | 100,000 |
| Enterprise | Custom $2,500-$5,000 | 10,000 | 1,000,000 |

A cycle is one rolling month anchored to the signup day. Every tier, including
Free, permits overage up to a hard cap of 3x the included limits. Beyond the cap,
new agents and handoffs return HTTP 402 until the next cycle or a tier upgrade.

### Live external payment links

The Cashfree merchant account collects in **INR only**. AgentGrid's internal
ledger and statements remain in **USD**. The operator uses this fixed conversion
rate for external collection:

| Tier | USD price | INR link amount | Public payment link |
|---|---:|---:|---|
| Free | $0 | — | No payment needed |
| Plus | $20 | ₹1,700 | `https://payments.cashfree.com/forms/agentgrid-plus` |
| Pro | $150 | ₹12,750 | `https://payments.cashfree.com/forms/agentgrid-pro` |
| Enterprise | $2,500–$5,000 customer-entered | ₹212,500–₹425,000 | `https://payments.cashfree.com/forms/agentgrid-enterprise` (create once) |

Fixed rate: **₹85 = $1**. These are reusable Cashfree **Payment Forms**, so many
customers can pay through the same link. The Plus and Pro form IDs are
`agentgrid_plus_1700` and `agentgrid_pro_12750`; they were created in live mode
and are publicly reachable (HTTP 200). Enterprise uses a shared form where the
customer enters an amount in the range above — there is no drag-to-set slider in
Cashfree — and the activation bridge rejects anything outside that range.

The `cashfree_order_id` recorded through the admin API is the **transaction order
ID** from the Cashfree dashboard, not the form/link ID. Quote the statement's
`invoice_id` when asking a customer to pay.

### Enterprise self-service form (create once)

Enterprise is now a shared form. Create it once in the Cashfree dashboard — no
AgentGrid code change or redeployment is needed:

1. In Cashfree, go to **Payment Gateway → Payment Forms → All → Create Payment
   Form**.
2. For **Amount configuration**, choose the option that lets the customer enter
   the amount (not a single fixed amount). Cashfree does not offer a true slider;
   the customer types an amount. Set, where the editor allows it:
   - *Minimum amount:* `₹212,500`
   - *Maximum amount:* `₹425,000`
   - *Payment For:* `AgentGrid Enterprise subscription - one rolling cycle (₹85 = $1)`
   - *Amount Title:* `AgentGrid Enterprise`
   - *Personalise URL:* `agentgrid-enterprise`
   - *Form ID:* `agentgrid_enterprise`
3. Add the required custom field **AgentGrid Client ID** (same as Plus/Pro).
   Keep the form's email field enabled; it must match the email used at
   AgentGrid registration for automatic recovery of a mistyped Client ID.
4. Save and publish. The public link is
   `https://payments.cashfree.com/forms/agentgrid-enterprise`.
5. Send the customer that link and the `invoice_id` from
   `GET /v1/billing/statement`. They enter any INR amount in the range; the USD
   base is simply `INR amount / 85`. Enterprise has no stored base amount, so the
   statement shows `base_fee_usd: null`, `base_fee_note: "custom amount agreed
   manually"`, and a `total_due_usd` that covers only metered overage.
6. The bridge activates Enterprise automatically when the signed webhook arrives.
   If the amount is outside ₹212,500–₹425,000, it is ignored — handle that as an
   exception (refund or re-pay at the correct amount), not as a support grant.
7. At cycle end, call
   `POST /v1/admin/clients/<client_id>/statements/<cycle_start>/record-payment`
   with the order/payment IDs to mark the statement paid.

Older per-customer Enterprise URLs (`agentgrid-enterprise-<client_id>`) still
work, but the shared form is preferred. Cycle-end recording still requires the
admin key and a valid TOTP code and is idempotent by order ID. No Cashfree server
key, webhook, or payment credential is stored in AgentGrid.

### Repeatable operator checklist

For **every** confirmed external payment (Plus, Pro, or Enterprise), do this:

1. In the Cashfree dashboard, confirm the payment and copy the **transaction order
   ID** and payment ID.
2. Compute the invoice ID to quote or cross-check:

   ```bash
   python scripts/operator_billing.py invoice --client cli_...
   ```

3. Activate the tier immediately:

   ```bash
   python scripts/operator_billing.py grant --client cli_... --tier plus \
     --order order_... --payment pay_...
   ```

4. At cycle end, mark the statement paid:

   ```bash
   python scripts/operator_billing.py record --client cli_... --cycle YYYY-MM-DD \
     --order order_... --payment pay_...
   ```

The helper reads the admin key and TOTP secret from `.env.production`, generates
a fresh code per call, and prints only status and non-sensitive fields. Repeat the
whole checklist each cycle — tier access expires at the cycle end.

### Operating cadence (you are human)

The separate `operator-automation` bridge activates routine payments
automatically once its webhook is registered. You do **not** need to watch
payments around the clock.

- Enable email/SMS alerts for successful transactions in the Cashfree dashboard.
  You act on exceptions; you do not have to sit on the dashboard.
- Check once or twice a day with the read-only commands below.
- If a webhook fails, use `operator_billing.py grant` manually — the admin
  endpoint is idempotent by order ID, so it is safe to retry.
- At launch there are no real customers, so this workload is currently zero.
- AgentGrid itself stays webhook-free and credential-free; the bridge is a
  different project with its own secrets.

**Verification status (2026-11-21):** the Payment Form webhook is registered and
Cashfree's signed dashboard test event was accepted by the bridge (`200`; ignored
only because the fixed sample payload has no AgentGrid Client ID). Synthetic
signed-webhook tests pass. A live ₹1 Payment Form payment was then made with the
temporary test client `livetest_20261120a`; the signed webhook reached the bridge
and produced `grant client=livetest_20261120a tier=plus ... status=200`, with the
account showing `tier=plus / active=True` and payment `current`. Instant
activation on a real transaction is therefore verified. The temporary ₹1 form
and its bridge environment flags were removed after the test.

### How to check payments are going well

1. **Cashfree dashboard → Payment Gateway → Orders** — source of truth for money
   received. Look for `order_id`, amount, status `PAID`, and timestamp.
2. **Cashfree dashboard → Developers → Webhooks → your URL → deliveries** — look
   for HTTP `200`. A `401` means webhook secret mismatch; `503` means the bridge
   is not configured or AgentGrid is unreachable.
3. **Bridge logs** (Hobby keeps runtime logs for about 30 minutes):

   ```powershell
   cd "C:\Users\santhoshchithira\Documents\Default Project\operator-automation"
   vercel logs --environment production -n 50
   ```

   A healthy line is `grant client=... tier=... order=... status=200`.
   `resolved_by_email=true` means the form had a mistyped Client ID and the
   bridge used the form email to find the right client; the corrected client ID
   is shown in that log line. `action=ignored` means the form's Client ID field
   is missing or invalid.
4. **AgentGrid read-only operator view** (uses the admin key + TOTP from
   `.env.production`, prints no secrets):

   ```powershell
   python scripts\operator_billing.py list --limit 20
   python scripts\operator_billing.py status --client cli_...
   ```

   `status` shows tier, access expiry, invoice ID, payment status, amount due,
   usage/hard caps, and the last 10 immutable billing events (grants and
   recorded payments). These endpoints require the admin key and valid TOTP.

Overage rates:

- $1 per 1,000 extra handoffs
- $0.10 per extra agent per day (prorated from creation to cycle end)

Usage units are written to an immutable ledger. `GET /v1/billing/statement`
returns `base_fee_usd`, overage counts and rates, `total_due_usd`, hard caps, and
an `invoice_id`. The `overage` flag in agent/handoff responses is metadata only;
Agent Card signatures still cover the original unsigned card payload.

## Operator workflow

1. The client calls `GET /v1/billing/statement` and notes its `invoice_id` and
   `total_due_usd`.
2. The operator sends the matching **external Cashfree Payment Form link** from
   the table above. All collection happens outside this service; no payment
   credentials are stored in AgentGrid.
3. The customer pays through that external link, enters their AgentGrid Client
   ID and the same email used at registration, and quotes the `invoice_id`.
4. The separate `operator-automation` bridge verifies the signed webhook and
   grants the paid tier immediately. If the Client ID is mistyped, the bridge
   resolves the correct client from the signed form email and retries the grant;
   no operator action is needed. The operator checks exceptions in the Cashfree
   dashboard and the bridge logs.
5. At cycle end, the operator records the external references through the admin
   API below. Both the admin key and a valid TOTP code are required.

No money, webhook, or payment credential lives inside AgentGrid. Activation is
automatic via the separate bridge; cycle-end settlement remains an explicit
operator action.

## Record a tier grant (current cycle)

Selects the paid tier for the current rolling cycle and applies it immediately.
Access expires at the current cycle end, so it must be renewed each cycle.

```bash
curl -X POST \
  https://agentgrid-pied.vercel.app/v1/admin/clients/cli_.../grant-access \
  -H 'X-AgentGrid-Admin-Key: <admin-key>' \
  -H 'X-AgentGrid-Admin-MFA: <6-digit-totp>' \
  -H 'Content-Type: application/json' \
  -d '{"tier":"pro","cashfree_order_id":"order_123","cashfree_payment_id":"pay_123"}'
```

`tier` must be `plus`, `pro`, or `enterprise`. IDs are restricted to
`[A-Za-z0-9_-]{3,128}`. This is idempotent by Cashfree order ID: reusing the same
order for the same client returns `duplicate: true`, and using it for a different
client returns HTTP 409.

## Recovery email

Public registration is open self-service (`POST /v1/clients/register` needs no
invite token). Both it and `POST /v1/admin/clients/register` accept an optional
`email`. Existing clients can set or change it with:

```bash
curl -X PATCH \
  https://agentgrid-pied.vercel.app/v1/clients/me/email \
  -H 'X-AgentGrid-API-Key: <api-key>' \
  -H 'Content-Type: application/json' \
  -d '{"email":"developer@example.com"}'
```

The bridge uses the email in the signed Cashfree payload only when the submitted
Client ID does not exist, calling the admin-only
`GET /v1/admin/clients/by-email/{email}` endpoint. No payment data is stored in
AgentGrid, and no email is logged by the bridge.

## Record a statement payment (cycle end)

Marks a closed-cycle statement paid after the external payment is confirmed.

```bash
curl -X POST \
  https://agentgrid-pied.vercel.app/v1/admin/clients/cli_.../statements/2026-11-18/record-payment \
  -H 'X-AgentGrid-Admin-Key: <admin-key>' \
  -H 'X-AgentGrid-Admin-MFA: <6-digit-totp>' \
  -H 'Content-Type: application/json' \
  -d '{"cashfree_order_id":"order_123","cashfree_payment_id":"pay_123"}'
```

The date in the path is the cycle start date from the statement. This is also
idempotent by order ID. Only the statement's `payment_status` and an immutable
`billing_history` row change.

## Synthetic verification (no real users or money)

The full billing loop can be validated without real customers, real payments, or
card details. Run these locally from the AgentGrid folder; they read secrets from
`.env.production` without printing them:

```bash
python scripts/verify_synthetic_billing.py
python scripts/verify_admin_registration.py
python scripts/smoke_test_vercel.py
```

`verify_synthetic_billing.py` creates a synthetic `synbill_...` client through the
admin API, generates genuine overage by creating 8 agents on the free tier
(5 included), checks the ledger-backed statement and hard caps, records a
synthetic Plus grant and a closed-cycle payment using `test_order_...` /
`test_pay_...` references, then verifies the status flip and idempotency. It also
confirms that open cycles cannot be paid and malformed order IDs are rejected.
The rows it writes to Neon are synthetic only; no money moves and no external
payment is created. `smoke_test_vercel.py` uses `smoke_...` clients and ephemeral
local Ed25519 keys.

## Security notes

- The admin key and TOTP secret are configured as Vercel environment variables
  and are never committed or displayed.
- Production fails closed if the signing key, admin MFA configuration, or
  registration token is missing.
- Order and payment IDs are validated before any state change; invalid tiers,
  IDs, keys, or MFA codes are rejected without modifying data.
- Audit metadata drops secret-looking fields before storage.
