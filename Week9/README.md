# Week 9 - Securing Django + PostgreSQL (TDI-803)

TicketDesk is a deliberately vulnerable lab app. Run it only on 127.0.0.1.

- `v0-baseline`: the original vulnerable app (selfcheck 0/9). It contains lab-only
  example secrets (a weak SECRET_KEY and the DB password "postgres"). They are not real credentials.
- `v1-hardened`: the hardened app (selfcheck 9/9).

The real `.env` is never committed. Copy `ticketdesk/.env.example` to `ticketdesk/.env`
and set your own values. Compare the versions with:
`git diff --stat v0-baseline v1-hardened`
