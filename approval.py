"""The user's phone, standing in as a local web page.

Everything the agent must not be able to do lives here: creating spending
authority, and approving a purchase that is too large to auto-approve. The
agent can *request* both, and receives only a URL. It cannot click it, and it
never holds the signing key -- the two MCP tools that touch this module return
links, never signatures.

ponytail: localhost HTTP standing in for a screen the issuer owns. In
production this page is served by Razorpay (or the user's bank, since RBI's AFA
rules require the approval to happen in a regulated channel) and the key lives
in the device's secure element rather than a file.
"""
import json, pathlib, threading, time, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

from core import IntentMandate, Envelope

PORT = 7777          # actual port, set by start()
BASE = f"http://127.0.0.1:{PORT}"
PENDING_FILE = pathlib.Path(__file__).parent / "pending.json"

_ctx = {}            # injected by mcp_server


# Pending requests live on disk, not in memory, for two reasons found the hard
# way: a link must survive the server restarting, and an editor may run more
# than one copy of the MCP server -- the instance holding the port has to be
# able to serve a request another instance staged.
def _load() -> dict:
    try:
        return json.loads(PENDING_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _save(d: dict):
    PENDING_FILE.write_text(json.dumps(d, indent=2))


def _put(key: str, rec: dict):
    d = _load(); d[key] = rec; _save(d)


def _rs(paise) -> str:
    return f"₹{paise / 100:,.2f}"


# ---------------------------------------------------------------- requests

def request_authority(**fields) -> dict:
    """Stage a mandate for the user to sign. Signs nothing."""
    req_id = uuid.uuid4().hex[:10]
    _put(req_id, {"kind": "grant", "fields": fields, "state": "pending"})
    return {"request_id": req_id, "url": f"{BASE}/grant/{req_id}"}


def request_cart_approval(cart_id: str) -> dict:
    _put(cart_id, {"kind": "cart", "cart_id": cart_id, "state": "pending"})
    return {"url": f"{BASE}/approve/{cart_id}"}


def status(req_id: str) -> str:
    return _load().get(req_id, {}).get("state", "unknown")


# ---------------------------------------------------------------- the page

PAGE = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>Approve</title><style>
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;
background:#0d1117;color:#e6edf3;font:15px/1.5 -apple-system,system-ui,sans-serif}}
.phone{{width:340px;background:#161b22;border:1px solid #30363d;border-radius:28px;padding:26px 22px;
box-shadow:0 18px 50px #0008}}
.brand{{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:#7d8590;margin-bottom:18px}}
h1{{font-size:19px;margin:0 0 4px}}.sub{{color:#7d8590;font-size:13px;margin-bottom:18px}}
.row{{display:flex;justify-content:space-between;gap:12px;padding:9px 0;border-bottom:1px solid #21262d}}
.row:last-of-type{{border:0}}.k{{color:#7d8590}}.v{{font-weight:600;text-align:right}}
.total{{margin-top:14px;padding-top:14px;border-top:2px solid #30363d;display:flex;
justify-content:space-between;font-size:19px;font-weight:700}}
.note{{margin:16px 0 0;padding:11px 13px;background:#0d1117;border-left:3px solid #388bfd;
border-radius:5px;font-size:13px;color:#a5adb8}}
form{{display:flex;gap:10px;margin-top:22px}}button{{flex:1;padding:13px;border:0;border-radius:11px;
font:600 15px inherit;cursor:pointer}}
.yes{{background:#238636;color:#fff}}.no{{background:#21262d;color:#e6edf3}}
.done{{text-align:center;padding:26px 0}}.big{{font-size:42px}}
</style><div class=phone><div class=brand>{brand}</div>{body}</div>"""

DONE = ('<div class=done><div class=big>{icon}</div><h1>{title}</h1>'
        '<div class=sub>{sub}</div></div>')


def _grant_body(f) -> str:
    rows = [("Total budget", _rs(f["budget_paise"])),
            ("Most per purchase", _rs(f["per_txn_paise"])),
            ("You approve above", _rs(f["countersign_above_paise"])),
            ("Merchant", "Any" if f["merchant_id"] == "*"
                         else _ctx.get("merchant_name") or f["merchant_id"]),
            ("Purchases allowed", str(f["max_uses"])),
            ("Expires", time.strftime("%d %b %Y", time.localtime(f["expires_at"])))]
    return ("<h1>Allow your agent to spend?</h1>"
            f"<div class=sub>{f['agent_id'].split(':')[-1]} is asking for a spending limit.</div>"
            + "".join(f"<div class=row><span class=k>{k}</span>"
                      f"<span class=v>{v}</span></div>" for k, v in rows)
            + f"<p class=note>“{f['constraints']}”</p>"
            "<form method=post><button class=no name=a value=no>Decline</button>"
            "<button class=yes name=a value=yes>Allow</button></form>")


def _cart_body(cart: dict) -> str:
    rows = "".join(
        f"<div class=row><span class=k>{i['name']} ×{i['qty']}</span>"
        f"<span class=v>{_rs(i['unit_paise'] * i['qty'])}</span></div>" for i in cart["items"])
    return ("<h1>Approve this purchase?</h1>"
            f"<div class=sub>{_ctx.get('merchant_name') or cart['merchant_id']}</div>" + rows
            + f"<div class=total><span>Total</span><span>{_rs(cart['total_paise'])}</span></div>"
            "<form method=post><button class=no name=a value=no>Decline</button>"
            "<button class=yes name=a value=yes>Approve</button></form>")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):        # keep the MCP stdio channel clean
        pass

    def _send(self, html: str, code: int = 200):
        raw = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _page(self, body: str) -> str:
        return PAGE.format(brand="Proof-of-Mandate", body=body)

    def _split(self):
        parts = self.path.strip("/").split("/")
        return (parts[0], parts[1]) if len(parts) == 2 else (None, None)

    def do_GET(self):
        kind, key = self._split()
        req = _load().get(key)
        if not req:
            return self._send(self._page(DONE.format(
                icon="\U0001f50e", title="Nothing to approve",
                sub="This link has expired or was already used.")), 404)
        if req["state"] != "pending":
            return self._send(self._page(DONE.format(
                icon="✓" if req["state"] == "approved" else "×",
                title=req["state"].title(), sub="You can close this page.")))
        if kind == "grant":
            return self._send(self._page(_grant_body(req["fields"])))
        env = _ctx["load_cart"](req["cart_id"])
        if env is None:
            return self._send(self._page(DONE.format(
                icon="\U0001f50e", title="Cart not found", sub="")), 404)
        self._send(self._page(_cart_body(env.body())))

    def do_POST(self):
        kind, key = self._split()
        req = _load().get(key)
        if not req or req["state"] != "pending":
            return self._send(self._page(DONE.format(
                icon="×", title="Expired", sub="")), 409)
        n = int(self.headers.get("Content-Length", 0))
        approved = b"a=yes" in self.rfile.read(n)
        if not approved:
            req["state"] = "declined"
            _put(key, req)
            return self._send(self._page(DONE.format(
                icon="×", title="Declined", sub="Nothing was signed.")))

        # The signature happens here, in the user's own context -- never in a
        # tool the agent can call.
        if kind == "grant":
            env = Envelope.wrap(IntentMandate(**req["fields"])).sign(
                _ctx["user_id"], _ctx["user_key"])
            _ctx["mandate_file"].write_text(json.dumps(env.to_dict(), indent=2))
            sub = "Your agent can now spend within these limits."
        else:
            env = _ctx["load_cart"](req["cart_id"])
            env.sign(_ctx["user_id"], _ctx["user_key"])
            _ctx["save_cart"](req["cart_id"], env)
            sub = "Tell your agent to go ahead."
        req["state"] = "approved"
        _put(key, req)
        self._send(self._page(DONE.format(icon="✓", title="Approved", sub=sub)))


def start(**ctx) -> bool:
    """Run the approval page in a background thread.

    Tries a small range of ports: an editor may already be running another copy
    of this server, and silently failing would hand the user a dead link.
    """
    global PORT, BASE
    _ctx.update(ctx)
    for port in range(7777, 7787):
        try:
            srv = HTTPServer(("127.0.0.1", port), _Handler)
        except OSError:
            continue
        PORT, BASE = port, f"http://127.0.0.1:{port}"
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return True
    return False
