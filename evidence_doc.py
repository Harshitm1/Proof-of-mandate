"""Render an evidence pack as the document a merchant actually sends.

An acquirer does not receive JSON. They receive a representment: a page that
states who authorized what, for how much, and why the merchant believes it.
This turns the audit chain into that page.
"""
import html, json
from datetime import datetime, timezone


def _rs(paise) -> str:
    return f"₹{paise / 100:,.2f}"


def _ts(t) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC")


def _check(ok: bool, label: str, detail: str) -> str:
    mark = "&#10003;" if ok else "&#10007;"
    cls = "pass" if ok else "fail"
    return (f'<li class="{cls}"><span class="mark">{mark}</span>'
            f'<span class="label">{html.escape(label)}</span>'
            f'<span class="detail">{html.escape(detail)}</span></li>')


def render(pack: dict) -> str:
    if not pack.get("found"):
        body = (f'<div class="verdict undefendable">NO RECORD</div>'
                f'<p class="lede">{html.escape(pack["conclusion"])}</p>')
        return _shell(pack.get("cart_id", "unknown"), body)

    c = pack["cryptographic_checks"]
    a = pack["authority_granted"]
    defensible = (c["user_signed_the_mandate"] and c["merchant_signed_the_cart"]
                  and c["audit_chain_intact"] and pack["settled"])

    items = "".join(
        f"<tr><td>{html.escape(i['name'])}</td><td class='num'>{i['qty']}</td>"
        f"<td class='num'>{_rs(i['unit_paise'])}</td>"
        f"<td class='num'>{_rs(i['qty'] * i['unit_paise'])}</td></tr>"
        for i in pack["items"])

    chain = "".join(
        f"<tr><td class='num'>{e['seq']}</td><td>{html.escape(e['event'])}</td>"
        f"<td class='mono'>{_ts(e['ts'])}</td>"
        f"<td class='mono hash'>{e['hash'][:16]}…</td></tr>"
        for e in pack["audit_entries"])

    checks = "".join([
        _check(c["user_signed_the_mandate"], "Customer signed the spending mandate",
               "ECDSA P-256. Only the customer's private key could produce this signature."),
        _check(c["merchant_signed_the_cart"], "Merchant signed the cart",
               "The charged amount is the merchant's own attestation, not the agent's claim."),
        _check(c["user_countersigned_the_cart"] or
               pack["charged_paise"] <= a.get("countersign_above_paise", 10**12),
               "Approval threshold satisfied",
               "Countersigned by the customer" if c["user_countersigned_the_cart"]
               else "Below the customer's threshold for individual approval."),
        _check(c["audit_chain_intact"], "Audit chain intact",
               "Every entry hashes the one before it. No record was altered after the fact."),
    ])

    rail = pack.get("rail_reference")
    rail_row = (f"<tr><th>Razorpay order</th><td class='mono'>{html.escape(rail)}</td></tr>"
                if rail else "")

    body = f"""
      <div class="verdict {'authorized' if defensible else 'incomplete'}">
        {'AUTHORIZED' if defensible else 'INCOMPLETE'}
      </div>
      <p class="lede">{html.escape(pack['conclusion'])}</p>

      <h2>The customer's instruction</h2>
      <blockquote>&ldquo;{html.escape(pack['user_stated_constraints'])}&rdquo;</blockquote>
      <p class="note">Recorded at the time authority was granted, in the customer's
      own words, and cryptographically signed by them.</p>

      <h2>Authority granted</h2>
      <table class="kv">
        <tr><th>Authorized by</th><td class="mono">{html.escape(pack['authorized_by'])}</td></tr>
        <tr><th>Total budget</th><td>{_rs(a['budget_paise'])}</td></tr>
        <tr><th>Per-transaction limit</th><td>{_rs(a['per_txn_paise'])}</td></tr>
        <tr><th>Merchant scope</th><td class="mono">{html.escape(a['merchant_scope'])}</td></tr>
        <tr><th>Authority expired</th><td>{_ts(a['expires_at'])}</td></tr>
        {rail_row}
      </table>

      <h2>What was charged</h2>
      <table class="items">
        <thead><tr><th>Item</th><th class="num">Qty</th><th class="num">Unit</th>
        <th class="num">Amount</th></tr></thead>
        <tbody>{items}</tbody>
        <tfoot><tr><td colspan="3">Total charged</td>
        <td class="num total">{_rs(pack['charged_paise'])}</td></tr></tfoot>
      </table>

      <h2>Cryptographic verification</h2>
      <ul class="checks">{checks}</ul>

      <h2>Audit chain</h2>
      <table class="chain">
        <thead><tr><th class="num">#</th><th>Event</th><th>Time</th><th>Hash</th></tr></thead>
        <tbody>{chain}</tbody>
      </table>
      <p class="note">Chain head <span class="mono">{pack['chain_head'][:32]}&hellip;</span>
      Altering any entry above changes every hash after it.</p>
    """
    return _shell(pack["cart_id"], body)


def _shell(cart_id: str, body: str) -> str:
    return f"""<!doctype html>
<meta charset="utf-8">
<title>Dispute evidence &middot; {html.escape(cart_id)}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         color: #1a1a1a; background: #f4f4f2; margin: 0; padding: 40px 20px; }}
  .sheet {{ max-width: 760px; margin: 0 auto; background: #fff; padding: 48px 56px;
            box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  header {{ border-bottom: 2px solid #1a1a1a; padding-bottom: 16px; margin-bottom: 28px;
            display: flex; justify-content: space-between; align-items: baseline; }}
  h1 {{ font-size: 19px; letter-spacing: .06em; text-transform: uppercase; margin: 0; }}
  .cartid {{ font-family: ui-monospace, Menlo, monospace; font-size: 13px; color: #666; }}
  h2 {{ font-size: 12px; letter-spacing: .1em; text-transform: uppercase; color: #666;
        margin: 32px 0 10px; border-bottom: 1px solid #e4e4e0; padding-bottom: 6px; }}
  .verdict {{ display: inline-block; font-size: 13px; font-weight: 700; letter-spacing: .1em;
              padding: 7px 16px; border-radius: 3px; }}
  .authorized {{ background: #0f6b3f; color: #fff; }}
  .incomplete, .undefendable {{ background: #8a1c1c; color: #fff; }}
  .lede {{ font-size: 16px; margin: 16px 0 0; }}
  blockquote {{ margin: 0; padding: 14px 20px; border-left: 3px solid #1a1a1a;
                background: #faf9f7; font-size: 17px; }}
  .note {{ font-size: 13px; color: #666; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #eeeeeb; }}
  .kv th {{ width: 200px; color: #666; font-weight: 500; }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .total {{ font-weight: 700; font-size: 16px; }}
  tfoot td {{ border-top: 2px solid #1a1a1a; border-bottom: none; padding-top: 10px; }}
  .mono, .hash {{ font-family: ui-monospace, Menlo, monospace; font-size: 12.5px; }}
  .checks {{ list-style: none; padding: 0; margin: 0; }}
  .checks li {{ display: grid; grid-template-columns: 24px 1fr; gap: 2px 8px;
                padding: 10px 0; border-bottom: 1px solid #eeeeeb; }}
  .mark {{ grid-row: span 2; font-size: 17px; }}
  .pass .mark {{ color: #0f6b3f; }}
  .fail .mark {{ color: #8a1c1c; }}
  .label {{ font-weight: 600; }}
  .detail {{ font-size: 13px; color: #666; }}
  footer {{ margin-top: 36px; padding-top: 14px; border-top: 1px solid #e4e4e0;
            font-size: 12px; color: #888; }}
  @media print {{ body {{ background: #fff; padding: 0; }}
                  .sheet {{ box-shadow: none; padding: 0; }} }}
</style>
<div class="sheet">
  <header>
    <h1>Dispute Evidence</h1>
    <span class="cartid">{html.escape(cart_id)}</span>
  </header>
  {body}
  <footer>
    Generated by Proof-of-Mandate. Every signature above is verifiable against the
    customer's and merchant's public keys; the audit chain is independently
    recomputable from the record.
  </footer>
</div>"""


def write(pack: dict, path: str = "evidence.html") -> str:
    with open(path, "w") as f:
        f.write(render(pack))
    return path
