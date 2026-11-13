from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from tickets.models import Ticket

DATA = {
    "alice": [("Phishing email reported by HR", "high",
               "User clicked a link in a fake payroll email. Mailbox under review."),
              ("VPN certificate expiring", "medium", "Renew before Friday.")],
    "bob": [("Ransomware note on file server FS-02", "critical",
             "Do NOT share outside the IR team. Backup restore in progress. Contact: bob@ticketdesk.local"),
            ("Printer firmware update", "low", "Low priority.")],
}


class Command(BaseCommand):
    help = "Create lab users (alice/alice, bob/bob, admin/admin) and sample tickets."

    def handle(self, *args, **opts):
        for name, tickets in DATA.items():
            user, _ = User.objects.get_or_create(username=name)
            user.set_password(name)          # password == username (lab only)
            user.save()
            for title, sev, desc in tickets:
                Ticket.objects.get_or_create(owner=user, title=title,
                                             defaults={"severity": sev, "description": desc})
        admin, _ = User.objects.get_or_create(username="admin")
        admin.is_staff = admin.is_superuser = True
        admin.set_password("admin")
        admin.save()
        self.stdout.write(self.style.SUCCESS("Seeded users alice, bob, admin and 4 tickets."))
