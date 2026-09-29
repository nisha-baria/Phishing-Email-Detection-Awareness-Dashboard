import csv
import os
import random

LEGIT_TEMPLATES = [
    (
        "hr@{org}.example.org",
        "Quarterly Policy Update",
        "Hello Team, please review the attached updated employee handbook at your convenience.",
        "https://portal.example.org/docs/handbook",
        "handbook.pdf",
    ),
    (
        "notifications@{org}.example.com",
        "Your Monthly Statement",
        "Dear Customer, your monthly e-statement is ready for view on the secure portal.",
        "https://billing.example.com/statements",
        "statement.pdf",
    ),
    (
        "registrar@univ.example.edu",
        "Upcoming Semester Schedule",
        "Please find the exam schedule and classroom allocation for the upcoming term.",
        "https://student.univ.example.edu/portal",
        "exam_schedule.pdf",
    ),
    (
        "it-support@{org}.example.com",
        "Scheduled Maintenance This Weekend",
        "The internal network will undergo scheduled maintenance from 2 AM to 4 AM UTC.",
        "https://status.example.com/maintenance",
        "",
    ),
]

PHISH_TEMPLATES = [
    (
        "security-alert@account-{org}.invalid.test",
        "URGENT: Verify Your Account Immediately",
        "Your account will be suspended within 24 hours. Verify your password now to avoid service termination.",
        "http://198.51.100.10/verify-account",
        "verification_form.pdf.exe",
    ),
    (
        "billing@secure-pay-update.invalid.test",
        "CRITICAL: Unpaid Invoice Notice",
        "Immediate action required. Please clear the pending transaction or legal escalation will commence.",
        "http://pay-portal.update.invalid.test/login?id=99",
        "invoice_902.scr",
    ),
    (
        "rewards@lucky-winner.example.net",
        "You Have Won a Gift Card!",
        "Dear user, you won $1,000. Claim your prize immediately by submitting your personal details.",
        "http://reward-claim.invalid.test/gift",
        "claim_form.bat",
    ),
    (
        "admin@it-desk-support.invalid.test",
        "Password Expiration Notice - Act Fast",
        "Your organizational password expires today. Click the link to update your login credentials immediately.",
        "http://192.0.2.45/portal/login.php",
        "credential_update.vbs",
    ),
]


def generate_synthetic_data(output_path="data/phishing_email_dataset.csv", n=600):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    orgs = ["acme", "nexus", "vertex", "global", "apex", "fintech"]

    records = []
    for i in range(1, n + 1):
        is_phish = random.choice([0, 1])
        org = random.choice(orgs)

        if is_phish:
            template = random.choice(PHISH_TEMPLATES)
            label = "PHISHING"
        else:
            template = random.choice(LEGIT_TEMPLATES)
            label = "LEGITIMATE"

        sender = template[0].format(org=org)
        domain = sender.split("@")[-1]
        subject = template[1]
        body = template[2]
        url = template[3]
        attachment = template[4]

        records.append(
            {
                "email_id": f"EML-{i:04d}",
                "sender": sender,
                "sender_domain": domain,
                "subject": subject,
                "body": body,
                "urls": url,
                "attachment_name": attachment,
                "label": label,
            }
        )

    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)

    print(
        f"[+] Successfully generated {len(records)} records at '{output_path}'."
    )


if __name__ == "__main__":
    generate_synthetic_data()