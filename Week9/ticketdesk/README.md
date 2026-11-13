# TicketDesk — Week 9 lab target (TDI-803 Ethical Hacking)

A small Django 5.2 + PostgreSQL 16 incident-ticket app. It was written "quickly, to get it working".
**It is insecure on purpose. Run it only on your own VM / localhost.**

## Run it (≈10 min)

```bash
cd ticketdesk
docker compose up -d db                        # PostgreSQL 16 in a container
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py seed                          # users: alice/alice, bob/bob, admin/admin
python manage.py runserver 127.0.0.1:8000      # open http://127.0.0.1:8000
python selfcheck.py                            # 9 security controls, PASS/FAIL
```

No Docker? Install PostgreSQL 16 locally (`sudo apt install postgresql`), set the `postgres`
user's password to `postgres` and create a database called `ticketdesk`.
Last resort only: `USE_SQLITE=1 python manage.py ...` (Part 3 of the lab needs PostgreSQL).

## Rules of Engagement
Your own copy, your own machine, `127.0.0.1` only. Never deploy this app publicly.
