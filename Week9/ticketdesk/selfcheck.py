#!/usr/bin/env python
"""
TicketDesk self-check - Week 9 lab (TDI-803).

Runs ONLY against this project, in-process, with Django's test client.
It sends nothing over the network. Run it before and after your fixes:

    python selfcheck.py

Each control prints PASS or FAIL. It tells you WHAT is still weak, not HOW to fix it.
Run `python manage.py seed` first so the lab users exist.
"""
import logging
import os
import sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ticketdesk.settings")
import django  # noqa: E402

django.setup()

from django.conf import settings  # noqa: E402
from django.contrib.auth import password_validation  # noqa: E402
from django.contrib.auth.hashers import get_hasher  # noqa: E402
from django.contrib.auth.models import User  # noqa: E402
from django.core.exceptions import ValidationError  # noqa: E402
from django.db import connection  # noqa: E402
from django.test import Client  # noqa: E402
from django.test.utils import setup_test_environment  # noqa: E402

from tickets.models import Ticket  # noqa: E402

logging.disable(logging.CRITICAL)  # keep the output readable
setup_test_environment()  # lets the test client talk to the app in-process
HOST = {"SERVER_NAME": "127.0.0.1"}
results = []


def report(code, name, ok, detail):
    results.append(ok)
    tag = "\033[92mPASS\033[0m" if ok else "\033[91mFAIL\033[0m"
    print(f"[{tag}] {code:<4} {name:<44} {detail}")


def get(client, path, **kw):
    return client.get(path, secure=True, **kw)


try:
    alice = User.objects.get(username="alice")
    bob = User.objects.get(username="bob")
except User.DoesNotExist:
    sys.exit("Run `python manage.py seed` first.")

alice_client = Client(**HOST)
alice_client.force_login(alice)
bob_ticket = Ticket.objects.filter(owner=bob).first()

print("\nTicketDesk self-check\n" + "-" * 78)

# C1 - security settings ---------------------------------------------------
weak_key = (settings.SECRET_KEY.startswith("django-insecure")
            or len(settings.SECRET_KEY) < 50 or len(set(settings.SECRET_KEY)) < 5)
key_in_source = settings.SECRET_KEY in open(os.path.join("ticketdesk", "settings.py")).read()
problems = []
if settings.DEBUG:
    problems.append("DEBUG is on")
if weak_key:
    problems.append("SECRET_KEY is weak")
if key_in_source:
    problems.append("SECRET_KEY is in source code")
if "*" in settings.ALLOWED_HOSTS:
    problems.append("ALLOWED_HOSTS has '*'")
report("C1", "Security settings (A02 Misconfiguration)", not problems,
       "; ".join(problems) or "DEBUG off, key from environment, hosts restricted")

# C2 - SQL injection in search ----------------------------------------------
payload = "zz' OR owner_id <> 0 --"
quiet = Client(raise_request_exception=False, **HOST)
quiet.force_login(alice)
r = get(quiet, "/search/", data={"q": payload})
leaked = bob_ticket is not None and bob_ticket.title.encode() in r.content
if r.status_code >= 500:
    report("C2", "Search query (A05 Injection)", False, "a quote in the search box crashes the app")
else:
    report("C2", "Search query (A05 Injection)", not leaked,
           "another user's ticket came back" if leaked else "payload treated as plain text")

# C3 - stored XSS in ticket description -------------------------------------
marker = '<b id="xss-probe">probe</b>'
probe = Ticket.objects.create(owner=alice, title="selfcheck probe", description=marker)
r = get(alice_client, f"/tickets/{probe.pk}/")
raw = marker.encode() in r.content
report("C3", "Ticket description output (A05 Injection)", not raw,
       "HTML rendered as-is" if raw else "HTML escaped on output")

# C4 - IDOR on ticket detail ------------------------------------------------
if bob_ticket:
    r = get(alice_client, f"/tickets/{bob_ticket.pk}/")
    report("C4", "Ticket ownership check (A01 Access Control)", r.status_code in (403, 404),
           f"alice opened bob's ticket (HTTP {r.status_code})" if r.status_code == 200
           else f"alice gets HTTP {r.status_code} for bob's ticket")

# C5 - delete: GET + CSRF ---------------------------------------------------
victim = Ticket.objects.create(owner=alice, title="selfcheck delete", description="x")
get(alice_client, f"/tickets/{victim.pk}/delete/")
deleted_by_get = not Ticket.objects.filter(pk=victim.pk).exists()
if deleted_by_get:
    victim = Ticket.objects.create(owner=alice, title="selfcheck delete", description="x")
csrf_client = Client(enforce_csrf_checks=True, **HOST)
csrf_client.force_login(alice)
csrf_client.post(f"/tickets/{victim.pk}/delete/", secure=True)
deleted_without_token = not Ticket.objects.filter(pk=victim.pk).exists()
problems = []
if deleted_by_get:
    problems.append("a GET request deletes")
if deleted_without_token:
    problems.append("POST without CSRF token deletes")
report("C5", "Delete endpoint (A01 / CSRF)", not problems,
       "; ".join(problems) or "POST only, CSRF token required")
Ticket.objects.filter(title__startswith="selfcheck").delete()

# C6 - export without login -------------------------------------------------
anon = Client(**HOST)
r = get(anon, "/export/")
exposed = r.status_code == 200 and b"owner" in r.content
staff_only = True
if not exposed:
    r2 = get(alice_client, "/export/")
    staff_only = not (r2.status_code == 200 and b"owner" in r2.content)
report("C6", "CSV export access (A01 Access Control)", not exposed and staff_only,
       "anyone can download all tickets" if exposed else
       ("any logged-in user can export everything" if not staff_only else "staff only"))

# C7 - password storage & policy -------------------------------------------
first = get_hasher().algorithm
try:
    password_validation.validate_password("a", user=alice)
    weak_ok = True
except ValidationError:
    weak_ok = False
problems = []
if first in ("md5", "unsalted_md5", "sha1", "unsalted_sha1"):
    problems.append(f"new passwords hashed with {first}")
if weak_ok:
    problems.append("password 'a' accepted")
report("C7", "Passwords (A04 Crypto / A07 Auth)", not problems,
       "; ".join(problems) or f"hasher={first}, validators active")

# C8 - session cookie -------------------------------------------------------
report("C8", "Session cookie flags (A02)", settings.SESSION_COOKIE_HTTPONLY,
       "HttpOnly on" if settings.SESSION_COOKIE_HTTPONLY else "cookie readable by JavaScript")

# C9 - database role --------------------------------------------------------
if connection.vendor == "postgresql":
    with connection.cursor() as cur:
        cur.execute("SELECT current_user, rolsuper, rolcreaterole, rolcreatedb "
                    "FROM pg_roles WHERE rolname = current_user")
        user, sup, crole, cdb = cur.fetchone()
    db_pw_in_source = settings.DATABASES["default"].get("PASSWORD", "") and \
        settings.DATABASES["default"]["PASSWORD"] in open(os.path.join("ticketdesk", "settings.py")).read()
    problems = []
    if sup or crole or cdb:
        problems.append(f"app connects as '{user}' with admin rights")
    if db_pw_in_source:
        problems.append("DB password in source code")
    report("C9", "Database role (least privilege)", not problems,
           "; ".join(problems) or f"app role '{user}' has no admin rights")
else:
    report("C9", "Database role (least privilege)", False, "not running on PostgreSQL")

print("-" * 78)
print(f"{sum(results)}/{len(results)} controls pass.\n")
