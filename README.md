# Proof-of-Mandate

**An authorization and evidence layer for AI agents that spend money.**

An agent buys something on your behalf. Weeks later the charge is disputed. Today
nobody can prove what you actually authorized — so the merchant eats the loss.

This bounds what an agent can spend *before* the payment, and proves what was
authorized *after* the dispute. Same audit trail does both jobs.

Built for the Razorpay AI Buildathon 2026 — Track 01, Agentic Commerce.

---

## The problem

Agent-initiated payments destroy the evidence that chargeback defence has always
relied on. There is no device fingerprint, no IP, no session — the merchant
receives a technically valid transaction with none of the context needed to
defend it. The industry calls this the *identity deficit at the point of payment*.

It is not a hypothetical:

- **37%** of merchants name fraud and dispute costs their top agentic-commerce concern
- **~2 in 3** say a standardised liability framework is urgently needed — none exists
- Agent traffic is up **805%**, but converts **86% worse** than affiliates, because
  merchant infrastructure was never built for agents
- Friendly fraud is already ~75% of all disputes; "I never approved that" gets
  much easier to say when a machine did the clicking

Demand is here. The rails are not.

## The idea

**Assume the agent is already compromised.**

Not "make the agent safer" — that is unachievable, and betting a payment system on
it is how you lose money. Instead, take money out of the agent's reach entirely:

> **The agent proposes. The gate disposes.**

The agent presents two signed documents. It authors neither.

| Document | Signed by | Carries |
|---|---|---|
| **Intent Mandate** | the **user** | what the agent may spend — budget, per-transaction cap, merchant scope, expiry, approval threshold |
| **Cart** | the **merchant** | what is actually being charged — line items and total |

The amount lives inside a merchant-signed cart, so **a prompt injection has no
number to tamper with.** Forging one requires the merchant's private key.

Above the user's threshold, the cart must additionally carry the **user's**
counter-signature — human-in-the-loop as a cryptographic requirement rather than
a dialog box. (This is AP2's human-present / human-not-present distinction.)

Every decision is written to a SHA-256 hash-chained log. When a dispute lands,
that log becomes the evidence pack.

## Results

Measured by [`attacks.py`](attacks.py). Fourteen attacks, each hitting a distinct
defence; eight benign purchases that must still succeed.

```
                                    gate OFF         gate ON
  attacks succeeding                      14               0
  unauthorised money moved         Rs 75,315            Rs 0

  legitimate purchases completed: 8/8  (false positives: 0)
```

A gate that refuses everything would be trivially "safe" and useless, so the
benign row is reported alongside: **8 of 8 legitimate purchases complete, zero
false positives.**

| Attack | Blocked by |
|---|---|
| Injected price inflation — agent edits a signed cart | `CART_UNSIGNED` |
| Forged mandate — agent mints unlimited authority | `INTENT_UNSIGNED` |
| Forged cart — attacker signs as the real merchant | `CART_UNSIGNED` |
| Counterfeit storefront (the Visa threat model) | `MERCHANT_NOT_ALLOWED` |
| Dishonest cart arithmetic | `CART_ARITHMETIC` |
| Expensive-SKU redirect — every signature valid | `PER_TXN_CAP` |
| Budget drain | `BUDGET_EXCEEDED` |
| Replay of a settled cart | `REPLAY` |
| Expired mandate / stale quote | `MANDATE_EXPIRED` / `CART_EXPIRED` |
| Agent counter-signs for the user | `COUNTERSIGN_REQUIRED` |
| Cart from another mandate | `CART_INTENT_MISMATCH` |
| Revoked mid-session | `MANDATE_REVOKED` |
| Over per-transaction cap | `PER_TXN_CAP` |

### Does prompt injection actually work?

Most agent-security demos assert that agents get fooled and move on. That claim
collapses under one skeptical question, because frontier models often catch the
obvious payloads. So [`injections.py`](injections.py) measures it — six graded
techniques from blatant fake system notices to pure helpfulness exploits.

The harness currently runs in `--dry` mode, which forces **total compliance at
every level** — the agent buys the attacker's bundle every time — and still moves
**Rs 0**. That result is independent of any model.

The per-level compliance column requires a live model run (`ANTHROPIC_API_KEY`)
and is **not yet filled in**. It is left empty rather than guessed.

## Try it

```bash
python3.12 -m venv .venv
.venv/bin/pip install cryptography "mcp[cli]" anthropic

.venv/bin/python test_core.py     # 21 tests
.venv/bin/python attacks.py       # the ablation above
.venv/bin/python injections.py --dry
```

### As an MCP server

[`.mcp.json`](.mcp.json) registers the server for Claude Code. Then ask Claude to
shop:

```
What's my shopping budget?
Buy me some atta                 -> paid, Rs 285
Buy me some basmati rice         -> the listing is prompt-injected
Buy me 2 litres of ghee          -> COUNTERSIGN_REQUIRED
```

When the gate allows, `pay()` creates a real **Razorpay test-mode Order** for the
approved amount and records the `order_id` in the audit chain and the evidence
pack. If the rail is unreachable, the gate returns `RAIL_UNAVAILABLE`, **no
budget is consumed**, and the cart stays payable — an outage at the payment
provider cannot silently burn the user's authority.

The tool surface is deliberately narrow. `pay()` takes a `cart_id` and **no
amount** — the agent has no way to express a number. And `approve` is *not* an
MCP tool: it lives in [`approve.py`](approve.py), a separate process holding the
user's key. An injected agent can ask for approval; it cannot grant it.

```bash
.venv/bin/python approve.py CART-XXXXXXXX
```

## Architecture

```
  user ──signs──> Intent Mandate ─┐
                                  ├──> [ GATE ] ──> settle ──> audit chain
  merchant ──signs──> Cart ───────┘       │                        │
                                          │                        v
  agent ──── may only present them ───────┘                  evidence pack
```

| File | Role |
|---|---|
| [`core.py`](core.py) | Mandates, signing, gate, hash-chained audit, evidence pack |
| [`mcp_server.py`](mcp_server.py) | MCP tools + demo merchant (one listing is injected) |
| [`approve.py`](approve.py) | The user's device. Out of the agent's reach, on purpose. |
| [`attacks.py`](attacks.py) | Adversarial suite and gate-on/off ablation |
| [`injections.py`](injections.py) | Graded injection suite |
| [`test_core.py`](test_core.py) | 23 assertions, one per deny path |

Crypto is ECDSA P-256 / SHA-256, matching the AP2 mandate spec. Public-key rather
than HMAC, and that is load-bearing: with a shared secret the merchant could have
forged the user's authorization, so the audit trail would prove nothing in a
dispute.

Money is integer paise throughout. No floats on a money path.

## Honest limitations

- **Payment stops at order creation.** When the gate allows, a real Razorpay
  test-mode Order is created for exactly the approved amount and its id is
  recorded in the audit chain. Completing a capture needs a customer at a
  checkout page, which a headless agent cannot do — so no capture is claimed.
- **Live-model injection compliance is unmeasured.** Harness ready, needs a key.
- **Gate state is in-memory**, single process. Marked in code; Redis is the swap.
- **The demo merchant is ours.** Real merchants do not expose agent checkout to
  third parties. AP2 and ACP reference implementations demo the same way.
- **Not a UPI integration.** We build the *shape* of a delegated mandate —
  signed, scoped, revocable. NPCI's Unified Agent Protocol is not yet public.

## Prior art

This is not a novel idea and the README should not pretend otherwise.

- **AP2** (Google, 60+ partners) — Intent/Cart/Payment mandates as W3C Verifiable
  Credentials. This project follows its mandate model and signature suite.
- **ACP** (OpenAI + Stripe) — Shared Payment Tokens: merchant-bound, amount-bound,
  time-bound, single-use.
- **CertNode** — binds mandate, cart and receipt into a self-authenticating
  evidence package. Closest commercial equivalent to this work.
- **Mastercard Verifiable Intent** — auditable consumer-consent trails.
- **Visa Trusted Agent Protocol** — agent identity and intent verification.

What is different here: the gate is measured adversarially with a published
ablation, the deny path is fully explainable, and it ships as an **MCP server**
so any Claude agent can transact through it.
