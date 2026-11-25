"""Ledgerline — a realistic, entirely synthetic, API-first multi-tenant billing
service used as a permanent end-to-end evaluation target for Vigilo (see README.md
and ground_truth.json in this directory).

There is no browser UI: ``/`` is a small JSON index linking to ``/v1`` and to the
OpenAPI 3.0 document (``/openapi.json``, also advertised by a
``Link: </openapi.json>; rel="service-desc"`` header on ``/v1``). Clients obtain an
opaque bearer token from ``POST /v1/auth/token`` (JSON or form body) and send it as
``Authorization: Bearer <token>``. No cookies.

Two organisations and three synthetic accounts (roles: admin > accountant > viewer):

    nadia / Nadia-Ledger-7731!x   admin       org_7Hq2 "Northwind Traders"
    omar  / Omar-View-4096#q      viewer      org_7Hq2 "Northwind Traders"
    greta / Greta-Books-2210$k    accountant  org_K9pX "Globex"

Seeded, non-destructive weaknesses (ground_truth.json):

B1  GET /v1/orgs/{org}/audit-events   documented ``x-required-role: admin`` but only
    tenant membership is checked: a viewer reads the full audit trail (actor
    emails, source IPs, actions).                                      vulnerability
B2  GET /v1/payments/{payment_id}     undocumented, reached via invoices'
    ``payment_id`` / ``_links.payment``; requires a token but never checks the
    payment's organisation (cross-tenant BOLA).                         vulnerability
B3  GET /v1/orgs/{org}/invoices?cursor=...   the cursor is base64url JSON
    ``{"org": ..., "offset": ...}``; membership is checked against the PATH org but
    the page is read from the CURSOR org (cross-tenant data exposure).  vulnerability

Negative controls: tenant membership on every /v1/orgs/{org}/... path (404),
settings admin-only (403), customer lookups tenant-scoped, the customers cursor is
validated against the path org, consistent 401 + WWW-Authenticate, no CORS headers
for any origin, X-RateLimit-* headers, correct JSON Content-Type, nosniff.
Reads never change state; POST/PATCH on invoices exist (role-checked, in-memory per
app instance) but no seeded issue depends on them.
"""
from __future__ import annotations

import base64
import binascii
import copy
import json
import random
import secrets
import string
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

SERVICE = "ledgerline-api"
VERSION = "2025-06-01"
TOKEN_TTL = 3600
RATE_LIMIT = 3000            # requests per minute per token / client address
DEFAULT_LIMIT = 10
MAX_LIMIT = 100
ROLE_RANK = {"viewer": 1, "accountant": 2, "admin": 3}
INVOICE_STATUSES = ("draft", "open", "paid", "void", "uncollectible")

ORGS = {
    "org_7Hq2": {"name": "Northwind Traders", "plan": "business", "country": "GB",
                 "domain": "northwind.example", "prefix": "NW", "currency": "GBP",
                 "created_at": "2023-03-14T09:12:44Z"},
    "org_K9pX": {"name": "Globex", "plan": "growth", "country": "US",
                 "domain": "globex.example", "prefix": "GX", "currency": "USD",
                 "created_at": "2023-08-02T16:40:03Z"},
}

# Accounts that can sign in (the evaluation's test accounts).
ACCOUNTS = {
    "nadia": {"password": "Nadia-Ledger-7731!x", "org": "org_7Hq2", "role": "admin",
              "name": "Nadia Rahimi", "email": "nadia.rahimi@northwind.example"},
    "omar": {"password": "Omar-View-4096#q", "org": "org_7Hq2", "role": "viewer",
             "name": "Omar Haddad", "email": "omar.haddad@northwind.example"},
    "greta": {"password": "Greta-Books-2210$k", "org": "org_K9pX", "role": "accountant",
              "name": "Greta Lindqvist", "email": "greta.lindqvist@globex.example"},
}
# Further org members (realistic member lists); nobody holds their credentials.
OTHER_MEMBERS = {
    "lena": {"org": "org_7Hq2", "role": "accountant", "name": "Lena Voss",
             "email": "lena.voss@northwind.example"},
    "hank": {"org": "org_K9pX", "role": "admin", "name": "Hank Scorpio",
             "email": "hank.scorpio@globex.example"},
    "ivy": {"org": "org_K9pX", "role": "viewer", "name": "Ivy Chen",
            "email": "ivy.chen@globex.example"},
}

_ALNUM = string.ascii_letters + string.digits
_EPOCH = datetime(2025, 1, 6, 9, 0, tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _generate() -> dict:
    """Deterministic synthetic dataset (stable ids across runs)."""
    rng = random.Random("ledgerline-fixture-v1")

    def rid(prefix: str, n: int = 14) -> str:
        return prefix + "".join(rng.choice(_ALNUM) for _ in range(n))

    users = {}
    for uname, u in {**ACCOUNTS, **OTHER_MEMBERS}.items():
        users[uname] = {"id": rid("usr_", 12), "username": uname, **{
            k: v for k, v in u.items() if k != "password"}}
    customer_names = {
        "org_7Hq2": ["Contoso Retail", "Fabrikam Logistics", "Tailspin Toys",
                     "Wingtip Supplies", "Litware Foods", "Proseware Ltd",
                     "Adatum Freight", "Lucerne Publishing", "Margie's Travel",
                     "Fourth Coffee", "Alpine Ski House", "Coho Vineyard"],
        "org_K9pX": ["Initech", "Umbrella Clinics", "Vandelay Industries",
                     "Soylent Partners", "Hooli Devices", "Stark Hardware",
                     "Wonka Confections", "Cyberdyne Labs", "Gringotts Holdings",
                     "Acme Rockets"],
    }
    n_invoices = {"org_7Hq2": 34, "org_K9pX": 27}
    customers: dict[str, dict] = {}
    invoices: dict[str, dict] = {}
    payments: dict[str, dict] = {}
    audit: dict[str, list] = {}
    for org_id, org in ORGS.items():
        cus = {}
        for i, cname in enumerate(customer_names[org_id]):
            slug = "".join(c for c in cname.lower() if c.isalnum())[:12]
            c = {"id": rid("cus_"), "object": "customer", "org_id": org_id,
                 "name": cname, "email": f"accounts@{slug}.example",
                 "country": rng.choice(["GB", "DE", "FR", "NL", "US", "IE", "ES"]),
                 "tax_id": f"{rng.choice(['GB', 'DE', 'FR', 'NL'])}"
                           f"{rng.randint(100000000, 999999999)}",
                 "created_at": _iso(_EPOCH - timedelta(days=400 - i * 9))}
            cus[c["id"]] = c
        customers[org_id] = cus
        cus_ids = list(cus)
        inv = {}
        for n in range(1, n_invoices[org_id] + 1):
            issued = _EPOCH + timedelta(days=n * 5, hours=rng.randint(0, 8))
            status = rng.choices(INVOICE_STATUSES, weights=[2, 5, 9, 1, 1])[0]
            amount = rng.randint(120, 48000) * 100 + rng.choice([0, 50, 99])
            cid = rng.choice(cus_ids)
            i = {"id": rid("inv_"), "object": "invoice", "org_id": org_id,
                 "number": f"{org['prefix']}-2025-{n:04d}", "customer_id": cid,
                 "status": status, "currency": org["currency"],
                 "amount_due": amount,
                 "amount_paid": amount if status == "paid" else 0,
                 "issued_at": _iso(issued), "due_at": _iso(issued + timedelta(days=30)),
                 "memo": None, "payment_id": None}
            if status == "paid":
                cust = cus[cid]
                p = {"id": rid("pay_"), "object": "payment", "org_id": org_id,
                     "invoice_id": i["id"], "customer_id": cid, "amount": amount,
                     "currency": org["currency"], "status": "succeeded",
                     "method": {"type": "card",
                                "brand": rng.choice(["visa", "mastercard", "amex"]),
                                "last4": f"{rng.randint(0, 9999):04d}",
                                "exp": f"{rng.randint(1, 12):02d}/{rng.randint(26, 30)}"},
                     "payer_email": f"ap.{rng.choice(['clerk', 'billing', 'finance'])}"
                                    f"{rng.randint(1, 9)}@"
                                    f"{cust['email'].split('@')[1]}",
                     "payer_name": rng.choice(["J. Patel", "M. Rossi", "A. Novak",
                                               "S. Okafor", "K. Tanaka", "L. Moreau"]),
                     "created_at": _iso(issued + timedelta(days=rng.randint(1, 25)))}
                payments[p["id"]] = p
                i["payment_id"] = p["id"]
            inv[i["id"]] = i
        invoices[org_id] = inv
        members = [u for u in users.values() if u["org"] == org_id]
        actions = ["user.login", "user.login", "invoice.created", "invoice.sent",
                   "invoice.voided", "member.invited", "member.role_changed",
                   "settings.webhook_updated", "api_key.created", "api_key.revoked",
                   "export.customers_csv", "user.mfa_disabled"]
        ev = []
        for k in range(18):
            actor = rng.choice(members)
            action = rng.choice(actions)
            target = {"invoice": lambda: rng.choice(list(inv)),
                      "member": lambda: rng.choice(members)["id"],
                      "api_key": lambda: rid("key_", 10)}.get(
                action.split(".")[0], lambda: org_id)()
            ev.append({"id": rid("evt_"), "object": "audit_event",
                       "occurred_at": _iso(_EPOCH + timedelta(days=k * 9,
                                                              minutes=rng.randint(0, 900))),
                       "actor": {"user_id": actor["id"], "email": actor["email"],
                                 "role": actor["role"]},
                       "action": action, "target": target,
                       "source_ip": rng.choice(["203.0.113.", "198.51.100.",
                                                "192.0.2."]) + str(rng.randint(2, 250)),
                       "user_agent": rng.choice(["Mozilla/5.0 (Windows NT 10.0)",
                                                 "ledgerline-cli/2.4.1",
                                                 "python-requests/2.32"])})
        audit[org_id] = sorted(ev, key=lambda e: e["occurred_at"], reverse=True)
    settings = {
        "org_7Hq2": {"billing_email": "billing@northwind.example",
                     "webhook": {"url": "https://hooks.northwind.example/ledgerline",
                                 "signing_secret": "whsec_****8f2a"}},
        "org_K9pX": {"billing_email": "ap@globex.example",
                     "webhook": {"url": "https://erp.globex.example/hooks/billing",
                                 "signing_secret": "whsec_****c41d"}},
    }
    return {"users": users, "customers": customers, "invoices": invoices,
            "payments": payments, "audit": audit, "settings": settings}


DATA = _generate()


# ---------------------------------------------------------------- cursors

def encode_cursor(doc: dict) -> str:
    raw = json.dumps(doc, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_cursor(cursor: str) -> dict | None:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        doc = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    try:
        doc["offset"] = int(doc.get("offset", 0))
    except (TypeError, ValueError):
        return None
    if doc["offset"] < 0 or not isinstance(doc.get("org"), str):
        return None
    return doc


# ---------------------------------------------------------------- state

class _Store:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.tokens: dict[str, tuple[str, float]] = {}
        self.invoices = copy.deepcopy(DATA["invoices"])
        self.rate: dict[str, tuple[int, int]] = {}
        self.hits: dict[str, int] = {}


def counts(app: Starlette) -> dict[str, int]:
    store: _Store = app.state.store
    with store.lock:
        return dict(store.hits)


# ---------------------------------------------------------------- responses

def _store(request: Request) -> _Store:
    return request.app.state.store


def _send(request: Request, body, status: int = 200,
          headers: dict | None = None) -> Response:
    resp = JSONResponse(body, status_code=status, headers=headers)
    store = _store(request)
    auth = request.headers.get("authorization", "")
    key = auth or (request.client.host if request.client else "-")
    window = int(time.time() // 60)
    with store.lock:
        w, n = store.rate.get(key, (window, 0))
        if w != window:
            w, n = window, 0
        store.rate[key] = (w, n + 1)
        store.hits[request.url.path] = store.hits.get(request.url.path, 0) + 1
    resp.headers["X-RateLimit-Limit"] = str(RATE_LIMIT)
    resp.headers["X-RateLimit-Remaining"] = str(max(0, RATE_LIMIT - n - 1))
    resp.headers["X-RateLimit-Reset"] = str((window + 1) * 60)
    resp.headers["X-Request-Id"] = "req_" + secrets.token_hex(8)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Ledgerline-Version"] = VERSION
    return resp


def _error(request: Request, status: int, code: str, message: str,
           headers: dict | None = None) -> Response:
    return _send(request, {"error": {"type": code, "message": message}}, status, headers)


def _limited(request: Request) -> Response | None:
    store = _store(request)
    key = request.headers.get("authorization", "") or (
        request.client.host if request.client else "-")
    with store.lock:
        w, n = store.rate.get(key, (0, 0))
    if w == int(time.time() // 60) and n >= RATE_LIMIT:
        return _error(request, 429, "rate_limited", "Too many requests.",
                      {"Retry-After": "60"})
    return None


def _unauth(request: Request, err: str | None, msg: str) -> Response:
    challenge = 'Bearer realm="ledgerline"'
    if err:
        challenge += f', error="{err}"'
    return _error(request, 401, "unauthorized", msg, {"WWW-Authenticate": challenge})


def _caller(request: Request) -> tuple[dict | None, Response | None]:
    limited = _limited(request)
    if limited:
        return None, limited
    header = request.headers.get("authorization", "")
    if not header:
        return None, _unauth(request, None, "Authentication required.")
    scheme, _, token = header.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        return None, _unauth(request, "invalid_request",
                             "Use the Authorization: Bearer scheme.")
    with _store(request).lock:
        entry = _store(request).tokens.get(token)
    if entry is None or entry[1] < time.time():
        return None, _unauth(request, "invalid_token",
                             "The access token is invalid or expired.")
    return DATA["users"][entry[0]], None


def _member(request: Request, user: dict, org_id: str) -> Response | None:
    """Tenant membership on the PATH org (unknown and foreign orgs look alike)."""
    if org_id not in ORGS or user["org"] != org_id:
        return _error(request, 404, "not_found", "No such organisation.")
    return None


def _role(request: Request, user: dict, minimum: str) -> Response | None:
    if ROLE_RANK[user["role"]] < ROLE_RANK[minimum]:
        return _error(request, 403, "forbidden",
                      f"This operation requires the {minimum} role.")
    return None


def _limit(request: Request) -> int | None:
    raw = request.query_params.get("limit")
    if raw is None:
        return DEFAULT_LIMIT
    try:
        n = int(raw)
    except ValueError:
        return None
    return n if 1 <= n <= MAX_LIMIT else None


def _page(items: list, org_id: str, offset: int, limit: int) -> dict:
    chunk = items[offset:offset + limit]
    more = offset + limit < len(items)
    return {"object": "list", "data": chunk, "has_more": more,
            "next_cursor": encode_cursor({"org": org_id, "offset": offset + limit})
            if more else None}


def _customer_view(c: dict) -> dict:
    base = f"/v1/orgs/{c['org_id']}/customers/{c['id']}"
    return {**c, "_links": {"self": {"href": base},
                            "invoices": {"href": base + "/invoices"}}}


def _invoice_view(i: dict) -> dict:
    org = i["org_id"]
    links = {"self": {"href": f"/v1/orgs/{org}/invoices/{i['id']}"},
             "customer": {"href": f"/v1/orgs/{org}/customers/{i['customer_id']}"}}
    if i.get("payment_id"):
        links["payment"] = {"href": f"/v1/payments/{i['payment_id']}"}
    return {**i, "_links": links}


# ---------------------------------------------------------------- handlers

async def index(request: Request) -> Response:
    return _send(request, {
        "service": SERVICE, "description": "Ledgerline billing API",
        "version": VERSION,
        "_links": {"v1": {"href": "/v1"},
                   "openapi": {"href": "/openapi.json",
                               "type": "application/json"},
                   "token": {"href": "/v1/auth/token"}}})


async def v1_index(request: Request) -> Response:
    return _send(request, {
        "version": VERSION,
        "_links": {"token": {"href": "/v1/auth/token"}, "me": {"href": "/v1/me"},
                   "orgs": {"href": "/v1/orgs/{org_id}", "templated": True},
                   "service-desc": {"href": "/openapi.json"}}},
        headers={"Link": '</openapi.json>; rel="service-desc"'})


async def openapi(request: Request) -> Response:
    return _send(request, OPENAPI)


async def token(request: Request) -> Response:
    limited = _limited(request)
    if limited:
        return limited
    raw = (await request.body()).decode("utf-8", "replace")
    ctype = request.headers.get("content-type", "")
    if "json" in ctype:
        try:
            body = json.loads(raw or "{}")
        except ValueError:
            body = None
    elif "x-www-form-urlencoded" in ctype:
        body = dict(parse_qsl(raw))
    else:
        return _send(request, {"error": "invalid_request",
                               "error_description": "Send JSON or form-encoded "
                                                    "username and password."}, 415)
    if not isinstance(body, dict) or not body.get("username") \
            or not body.get("password"):
        return _send(request, {"error": "invalid_request",
                               "error_description": "username and password are "
                                                    "required."}, 400)
    if body.get("grant_type") not in (None, "password"):
        return _send(request, {"error": "unsupported_grant_type"}, 400)
    user = str(body["username"])
    acct = ACCOUNTS.get(user)
    if acct is None or not secrets.compare_digest(str(body["password"]),
                                                  acct["password"]):
        return _send(request, {"error": "invalid_grant",
                               "error_description": "Invalid username or password."},
                     401)
    tok = secrets.token_urlsafe(32)
    with _store(request).lock:
        _store(request).tokens[tok] = (user, time.time() + TOKEN_TTL)
    return _send(request, {"access_token": tok, "token_type": "Bearer",
                           "expires_in": TOKEN_TTL})


async def me(request: Request) -> Response:
    user, err = _caller(request)
    if err:
        return err
    return _send(request, {**{k: user[k] for k in ("id", "username", "name", "email",
                                                   "role")},
                           "object": "user", "org_id": user["org"],
                           "_links": {"org": {"href": f"/v1/orgs/{user['org']}"}}})


async def org(request: Request) -> Response:
    user, err = _caller(request)
    if err:
        return err
    org_id = request.path_params["org_id"]
    if (denied := _member(request, user, org_id)):
        return denied
    o = ORGS[org_id]
    base = f"/v1/orgs/{org_id}"
    return _send(request, {
        "id": org_id, "object": "organization", "name": o["name"], "plan": o["plan"],
        "country": o["country"], "default_currency": o["currency"],
        "created_at": o["created_at"],
        "_links": {k: {"href": f"{base}/{k}"} for k in
                   ("customers", "invoices", "members", "settings", "audit-events")}})


async def customers(request: Request) -> Response:
    user, err = _caller(request)
    if err:
        return err
    org_id = request.path_params["org_id"]
    if (denied := _member(request, user, org_id)):
        return denied
    limit = _limit(request)
    if limit is None:
        return _error(request, 400, "invalid_request",
                      f"limit must be between 1 and {MAX_LIMIT}.")
    offset = 0
    if (cur := request.query_params.get("cursor")):
        doc = decode_cursor(cur)
        # negative control: the customers cursor is bound to the path org
        if doc is None or doc["org"] != org_id:
            return _error(request, 400, "invalid_cursor", "Invalid cursor.")
        offset = doc["offset"]
    items = sorted(DATA["customers"][org_id].values(), key=lambda c: c["created_at"])
    if (email := request.query_params.get("email")):
        items = [c for c in items if c["email"].lower() == email.lower()]
    if (q := request.query_params.get("q")):
        items = [c for c in items if q.lower() in c["name"].lower()]
    if (country := request.query_params.get("country")):
        items = [c for c in items if c["country"] == country.upper()]
    page = _page([_customer_view(c) for c in items], org_id, offset, limit)
    return _send(request, page)


async def customer(request: Request) -> Response:
    user, err = _caller(request)
    if err:
        return err
    org_id = request.path_params["org_id"]
    if (denied := _member(request, user, org_id)):
        return denied
    c = DATA["customers"][org_id].get(request.path_params["customer_id"])
    if c is None:
        return _error(request, 404, "not_found", "No such customer.")
    return _send(request, _customer_view(c))


async def customer_invoices(request: Request) -> Response:
    user, err = _caller(request)
    if err:
        return err
    org_id = request.path_params["org_id"]
    if (denied := _member(request, user, org_id)):
        return denied
    cid = request.path_params["customer_id"]
    if cid not in DATA["customers"][org_id]:
        return _error(request, 404, "not_found", "No such customer.")
    with _store(request).lock:
        items = [_invoice_view(i) for i in _store(request).invoices[org_id].values()
                 if i["customer_id"] == cid]
    return _send(request, {"object": "list", "data": items, "has_more": False,
                           "next_cursor": None})


async def invoices(request: Request) -> Response:
    user, err = _caller(request)
    if err:
        return err
    org_id = request.path_params["org_id"]
    if (denied := _member(request, user, org_id)):
        return denied
    if request.method == "POST":
        return await _create_invoice(request, user, org_id)
    limit = _limit(request)
    if limit is None:
        return _error(request, 400, "invalid_request",
                      f"limit must be between 1 and {MAX_LIMIT}.")
    status = request.query_params.get("status")
    if status is not None and status not in INVOICE_STATUSES:
        return _error(request, 400, "invalid_request",
                      "status must be one of " + ", ".join(INVOICE_STATUSES) + ".")
    scope, offset = org_id, 0
    if (cur := request.query_params.get("cursor")):
        doc = decode_cursor(cur)
        if doc is None:
            return _error(request, 400, "invalid_cursor", "Invalid cursor.")
        # B3: membership was checked on the PATH org; the page comes from the cursor
        scope, offset = doc["org"], doc["offset"]
    with _store(request).lock:
        items = list(_store(request).invoices.get(scope, {}).values())
    items.sort(key=lambda i: i["issued_at"], reverse=True)
    if status:
        items = [i for i in items if i["status"] == status]
    if (cid := request.query_params.get("customer_id")):
        items = [i for i in items if i["customer_id"] == cid]
    return _send(request, _page([_invoice_view(i) for i in items], scope, offset, limit))


async def _create_invoice(request: Request, user: dict, org_id: str) -> Response:
    if (denied := _role(request, user, "accountant")):
        return denied
    try:
        body = json.loads(await request.body() or b"{}")
    except ValueError:
        body = None
    if not isinstance(body, dict):
        return _error(request, 400, "invalid_request", "JSON body required.")
    cid, amount = body.get("customer_id"), body.get("amount_due")
    if cid not in DATA["customers"][org_id]:
        return _error(request, 422, "validation_error", "Unknown customer_id.")
    if not isinstance(amount, int) or not 1 <= amount <= 10_000_000_00:
        return _error(request, 422, "validation_error",
                      "amount_due must be a positive integer (minor units).")
    store = _store(request)
    with store.lock:
        n = len(store.invoices[org_id]) + 1
        now = datetime.now(timezone.utc)
        inv = {"id": "inv_" + "".join(secrets.choice(_ALNUM) for _ in range(14)),
               "object": "invoice", "org_id": org_id,
               "number": f"{ORGS[org_id]['prefix']}-2025-{n:04d}", "customer_id": cid,
               "status": "draft", "currency": ORGS[org_id]["currency"],
               "amount_due": amount, "amount_paid": 0, "issued_at": _iso(now),
               "due_at": _iso(now + timedelta(days=30)),
               "memo": str(body.get("memo"))[:500] if body.get("memo") else None,
               "payment_id": None}
        store.invoices[org_id][inv["id"]] = inv
    return _send(request, _invoice_view(inv), 201)


async def invoice(request: Request) -> Response:
    user, err = _caller(request)
    if err:
        return err
    org_id = request.path_params["org_id"]
    if (denied := _member(request, user, org_id)):
        return denied
    store = _store(request)
    with store.lock:
        inv = store.invoices[org_id].get(request.path_params["invoice_id"])
    if inv is None:
        return _error(request, 404, "not_found", "No such invoice.")
    if request.method == "PATCH":
        if (denied := _role(request, user, "accountant")):
            return denied
        try:
            body = json.loads(await request.body() or b"{}")
        except ValueError:
            body = None
        if not isinstance(body, dict) or not set(body) <= {"memo", "status", "due_at"}:
            return _error(request, 422, "validation_error",
                          "Only memo, status and due_at can be changed.")
        if "status" in body and body["status"] not in ("open", "void", "uncollectible"):
            return _error(request, 422, "validation_error", "Invalid status transition.")
        with store.lock:
            inv.update({k: (str(v)[:500] if k == "memo" and v is not None else v)
                        for k, v in body.items()})
    return _send(request, _invoice_view(inv))


async def members(request: Request) -> Response:
    user, err = _caller(request)
    if err:
        return err
    org_id = request.path_params["org_id"]
    if (denied := _member(request, user, org_id)):
        return denied
    data = [{"id": u["id"], "object": "member", "name": u["name"], "email": u["email"],
             "role": u["role"], "status": "active"}
            for u in DATA["users"].values() if u["org"] == org_id]
    return _send(request, {"object": "list", "data": data, "has_more": False,
                           "next_cursor": None})


async def settings(request: Request) -> Response:
    user, err = _caller(request)
    if err:
        return err
    org_id = request.path_params["org_id"]
    if (denied := _member(request, user, org_id)):
        return denied
    if (denied := _role(request, user, "admin")):          # negative control
        return denied
    o = ORGS[org_id]
    return _send(request, {"object": "org_settings", "org_id": org_id,
                           "default_currency": o["currency"],
                           "invoice_prefix": o["prefix"], "tax_behavior": "exclusive",
                           "sso_enforced": False, "mfa_required": True,
                           **DATA["settings"][org_id]})


async def audit_events(request: Request) -> Response:
    user, err = _caller(request)
    if err:
        return err
    org_id = request.path_params["org_id"]
    if (denied := _member(request, user, org_id)):
        return denied
    # B1: documented x-required-role: admin, but no role check here
    limit = _limit(request) if "limit" in request.query_params else MAX_LIMIT
    if limit is None:
        return _error(request, 400, "invalid_request",
                      f"limit must be between 1 and {MAX_LIMIT}.")
    items = DATA["audit"][org_id]
    if (action := request.query_params.get("action")):
        items = [e for e in items if e["action"] == action]
    return _send(request, {"object": "list", "data": items[:limit],
                           "has_more": len(items) > limit, "next_cursor": None})


async def payment(request: Request) -> Response:
    user, err = _caller(request)
    if err:
        return err
    # B2: undocumented; any valid token reads any organisation's payment
    p = DATA["payments"].get(request.path_params["payment_id"])
    if p is None:
        return _error(request, 404, "not_found", "No such payment.")
    return _send(request, {**p, "_links": {"invoice": {
        "href": f"/v1/orgs/{p['org_id']}/invoices/{p['invoice_id']}"}}})


async def not_found(request: Request, exc: Exception) -> Response:
    if isinstance(exc, HTTPException) and exc.status_code == 405:
        return _error(request, 405, "method_not_allowed", "Method not allowed.")
    return _error(request, 404, "not_found", "Not found.")


# ---------------------------------------------------------------- OpenAPI

def _ref(name: str) -> dict:
    return {"$ref": f"#/components/schemas/{name}"}


def _param(name: str, where: str = "path", desc: str = "", schema=None,
           required: bool | None = None) -> dict:
    return {"name": name, "in": where,
            "required": where == "path" if required is None else required,
            "description": desc, "schema": schema or {"type": "string"}}


_ORG = _param("org_id", desc="Organisation id, e.g. org_…")
_LIMIT = _param("limit", "query", f"Page size (1-{MAX_LIMIT}, default {DEFAULT_LIMIT}).",
                {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT,
                 "default": DEFAULT_LIMIT})
_CURSOR = _param("cursor", "query",
                 "Opaque pagination cursor: pass the next_cursor of the previous page.")
_ERRORS = {"401": {"$ref": "#/components/responses/Unauthorized"},
           "404": {"$ref": "#/components/responses/NotFound"}}


def _ok(schema: dict, desc: str = "OK") -> dict:
    return {"description": desc, "content": {"application/json": {"schema": schema}}}


def _list_of(name: str) -> dict:
    return {"allOf": [_ref("ListEnvelope"), {"type": "object", "properties": {
        "data": {"type": "array", "items": _ref(name)}}}]}


def _op(op_id: str, summary: str, tag: str, params: list, ok: dict,
        role: str | None = None, extra: dict | None = None, body: dict | None = None,
        code: str = "200") -> dict:
    op = {"operationId": op_id, "summary": summary, "tags": [tag],
          "parameters": params, "responses": {code: ok, **_ERRORS, **(extra or {})}}
    if role:
        op["x-required-role"] = role
        op["responses"]["403"] = {"$ref": "#/components/responses/Forbidden"}
    if body:
        op["requestBody"] = {"required": True, "content": {
            "application/json": {"schema": body}}}
    return op


_LINK = {"type": "object", "properties": {"href": {"type": "string"}}}
OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "Ledgerline API", "version": VERSION,
             "description": "Multi-tenant invoicing and billing API. Every resource "
                            "lives under an organisation; members see only their own "
                            "organisation. Monetary amounts are integers in minor "
                            "units. Role-restricted operations carry "
                            "`x-required-role` (admin > accountant > viewer).",
             "contact": {"name": "Ledgerline Platform", "email": "api@ledgerline.example"}},
    "servers": [{"url": "/"}],
    "security": [{"bearerAuth": []}],
    "tags": [{"name": n} for n in ("auth", "users", "organizations", "customers",
                                   "invoices", "members", "audit")],
    "paths": {
        "/v1/auth/token": {"post": {
            "operationId": "createToken", "summary": "Exchange credentials for an "
                                                     "access token", "tags": ["auth"],
            "security": [],
            "requestBody": {"required": True, "content": {
                "application/json": {"schema": _ref("TokenRequest")},
                "application/x-www-form-urlencoded": {"schema": _ref("TokenRequest")}}},
            "responses": {"200": _ok(_ref("TokenResponse")),
                          "400": {"description": "Malformed request"},
                          "401": {"description": "Invalid credentials"}}}},
        "/v1/me": {"get": _op("getMe", "The authenticated user", "users", [],
                              _ok(_ref("User")))},
        "/v1/orgs/{org_id}": {"get": _op("getOrganization", "Organisation", "organizations",
                                         [_ORG], _ok(_ref("Organization")))},
        "/v1/orgs/{org_id}/customers": {"get": _op(
            "listCustomers", "List customers", "customers",
            [_ORG, _LIMIT, _CURSOR,
             _param("email", "query", "Exact e-mail match."),
             _param("q", "query", "Case-insensitive substring of the name."),
             _param("country", "query", "ISO 3166-1 alpha-2 country code.")],
            _ok(_list_of("Customer")))},
        "/v1/orgs/{org_id}/customers/{customer_id}": {"get": _op(
            "getCustomer", "Retrieve a customer", "customers",
            [_ORG, _param("customer_id", desc="cus_…")], _ok(_ref("Customer")))},
        "/v1/orgs/{org_id}/customers/{customer_id}/invoices": {"get": _op(
            "listCustomerInvoices", "A customer's invoices", "customers",
            [_ORG, _param("customer_id", desc="cus_…")], _ok(_list_of("Invoice")))},
        "/v1/orgs/{org_id}/invoices": {
            "get": _op("listInvoices", "List invoices", "invoices",
                       [_ORG, _param("status", "query", "Filter by status.",
                                     {"type": "string", "enum": list(INVOICE_STATUSES)}),
                        _param("customer_id", "query", "Filter by customer (cus_…)."),
                        _LIMIT, _CURSOR],
                       _ok(_list_of("Invoice"))),
            "post": _op("createInvoice", "Create a draft invoice", "invoices", [_ORG],
                        _ok(_ref("Invoice"), "Created"), role="accountant",
                        body=_ref("InvoiceCreate"), code="201",
                        extra={"422": {"description": "Validation error"}})},
        "/v1/orgs/{org_id}/invoices/{invoice_id}": {
            "get": _op("getInvoice", "Retrieve an invoice", "invoices",
                       [_ORG, _param("invoice_id", desc="inv_…")], _ok(_ref("Invoice"))),
            "patch": _op("updateInvoice", "Update an invoice", "invoices",
                         [_ORG, _param("invoice_id", desc="inv_…")], _ok(_ref("Invoice")),
                         role="accountant", body=_ref("InvoiceUpdate"),
                         extra={"422": {"description": "Validation error"}})},
        "/v1/orgs/{org_id}/members": {"get": _op(
            "listMembers", "Organisation members", "members", [_ORG],
            _ok(_list_of("Member")))},
        "/v1/orgs/{org_id}/settings": {"get": _op(
            "getSettings", "Organisation billing settings", "organizations", [_ORG],
            _ok(_ref("Settings")), role="admin")},
        "/v1/orgs/{org_id}/audit-events": {"get": _op(
            "listAuditEvents", "Security audit trail of the organisation", "audit",
            [_ORG, _LIMIT, _param("action", "query", "Filter by action, e.g. user.login.")],
            _ok(_list_of("AuditEvent")), role="admin")},
    },
    "components": {
        "securitySchemes": {"bearerAuth": {
            "type": "http", "scheme": "bearer",
            "description": "Opaque access token from POST /v1/auth/token."}},
        "responses": {
            "Unauthorized": {"description": "Missing or invalid token",
                             "content": {"application/json": {"schema": _ref("Error")}}},
            "Forbidden": {"description": "Role not sufficient",
                          "content": {"application/json": {"schema": _ref("Error")}}},
            "NotFound": {"description": "Not found (or not in your organisation)",
                         "content": {"application/json": {"schema": _ref("Error")}}}},
        "schemas": {
            "Error": {"type": "object", "properties": {"error": {
                "type": "object", "properties": {"type": {"type": "string"},
                                                 "message": {"type": "string"}}}}},
            "TokenRequest": {"type": "object", "required": ["username", "password"],
                             "properties": {"username": {"type": "string"},
                                            "password": {"type": "string",
                                                         "format": "password"},
                                            "grant_type": {"type": "string",
                                                           "enum": ["password"]}}},
            "TokenResponse": {"type": "object", "properties": {
                "access_token": {"type": "string"},
                "token_type": {"type": "string", "example": "Bearer"},
                "expires_in": {"type": "integer", "example": TOKEN_TTL}}},
            "ListEnvelope": {"type": "object", "properties": {
                "object": {"type": "string", "example": "list"},
                "has_more": {"type": "boolean"},
                "next_cursor": {"type": "string", "nullable": True}}},
            "User": {"type": "object", "properties": {
                k: {"type": "string"} for k in ("id", "username", "name", "email",
                                                "role", "org_id")}},
            "Organization": {"type": "object", "properties": {
                k: {"type": "string"} for k in ("id", "name", "plan", "country",
                                                "default_currency", "created_at")}},
            "Customer": {"type": "object", "properties": {
                **{k: {"type": "string"} for k in ("id", "org_id", "name", "email",
                                                   "country", "tax_id", "created_at")},
                "_links": {"type": "object", "additionalProperties": _LINK}}},
            "Invoice": {"type": "object", "properties": {
                **{k: {"type": "string"} for k in ("id", "org_id", "number",
                                                   "customer_id", "currency",
                                                   "issued_at", "due_at")},
                "status": {"type": "string", "enum": list(INVOICE_STATUSES)},
                "amount_due": {"type": "integer"}, "amount_paid": {"type": "integer"},
                "memo": {"type": "string", "nullable": True},
                "payment_id": {"type": "string", "nullable": True,
                               "description": "Settling payment (pay_…), if paid."},
                "_links": {"type": "object", "additionalProperties": _LINK}}},
            "InvoiceCreate": {"type": "object", "required": ["customer_id", "amount_due"],
                              "properties": {"customer_id": {"type": "string"},
                                             "amount_due": {"type": "integer"},
                                             "memo": {"type": "string"}}},
            "InvoiceUpdate": {"type": "object", "properties": {
                "memo": {"type": "string"}, "due_at": {"type": "string"},
                "status": {"type": "string", "enum": ["open", "void", "uncollectible"]}}},
            "Member": {"type": "object", "properties": {
                k: {"type": "string"} for k in ("id", "name", "email", "role", "status")}},
            "Settings": {"type": "object", "properties": {
                "billing_email": {"type": "string"}, "default_currency": {"type": "string"},
                "invoice_prefix": {"type": "string"}, "tax_behavior": {"type": "string"},
                "sso_enforced": {"type": "boolean"}, "mfa_required": {"type": "boolean"},
                "webhook": {"type": "object", "properties": {
                    "url": {"type": "string"}, "signing_secret": {"type": "string"}}}}},
            "AuditEvent": {"type": "object", "properties": {
                "id": {"type": "string"}, "occurred_at": {"type": "string"},
                "action": {"type": "string"}, "target": {"type": "string"},
                "source_ip": {"type": "string"}, "user_agent": {"type": "string"},
                "actor": {"type": "object", "properties": {
                    k: {"type": "string"} for k in ("user_id", "email", "role")}}}},
        },
    },
}


# ---------------------------------------------------------------- app

def build_app() -> Starlette:
    app = Starlette(routes=[
        Route("/", index),
        Route("/openapi.json", openapi),
        Route("/v1", v1_index),
        Route("/v1/auth/token", token, methods=["POST"]),
        Route("/v1/me", me),
        Route("/v1/orgs/{org_id}", org),
        Route("/v1/orgs/{org_id}/customers", customers),
        Route("/v1/orgs/{org_id}/customers/{customer_id}", customer),
        Route("/v1/orgs/{org_id}/customers/{customer_id}/invoices", customer_invoices),
        Route("/v1/orgs/{org_id}/invoices", invoices, methods=["GET", "POST"]),
        Route("/v1/orgs/{org_id}/invoices/{invoice_id}", invoice,
              methods=["GET", "PATCH"]),
        Route("/v1/orgs/{org_id}/members", members),
        Route("/v1/orgs/{org_id}/settings", settings),
        Route("/v1/orgs/{org_id}/audit-events", audit_events),
        Route("/v1/payments/{payment_id}", payment),      # B2: not in OPENAPI
    ], exception_handlers={404: not_found, 405: not_found})
    app.state.store = _Store()
    return app


def serve(port: int = 0, host: str = "127.0.0.1", blocking: bool = False):
    import uvicorn
    config = uvicorn.Config(build_app(), host=host, port=port, log_level="warning",
                            lifespan="off", access_log=False, server_header=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True, name="ledgerline-api")
    thread.start()
    while not server.started:
        time.sleep(0.01)
    url = f"http://{host}:{server.servers[0].sockets[0].getsockname()[1]}/"
    if blocking:
        thread.join()
    return server, url
