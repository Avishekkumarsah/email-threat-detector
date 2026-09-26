"""
make_sample_dataset.py
-----------------------
Creates a small starter dataset.csv so the project trains and runs
immediately. This is NOT a substitute for a real dataset - for your
actual submission, download a proper phishing/spam dataset (search
Kaggle for "phishing email dataset" or "SpamAssassin corpus") and
replace data/dataset.csv with it, keeping the same column names:
    text, label   (label: 1 = phishing/spam, 0 = legitimate)
"""

import csv
import os
import random

PHISHING_TEMPLATES = [
    "Urgent: your account has been suspended. Verify your account now by clicking here.",
    "Dear customer, we noticed unusual activity. Confirm your password immediately.",
    "Congratulations! You have won a prize. Click here to claim your reward now.",
    "Action required: your payment failed. Update your billing information urgently.",
    "Your account will be locked in 24 hours. Verify your identity immediately.",
    "Security alert: unusual login detected. Reset your password now to secure your account.",
    "Final notice: wire transfer required today to avoid account suspension.",
    "Your package could not be delivered. Confirm your address by clicking the link below.",
    "Limited time offer! Verify your account to avoid permanent suspension.",
    "We detected suspicious activity on your account. Act now to prevent closure.",
    "Your invoice is overdue. Click here immediately to make a payment and avoid penalty.",
    "Dear user, your mailbox is full. Click here now to increase storage before it is deleted.",
    "Your subscription has expired. Renew now by confirming your card details urgently.",
    "Alert: someone tried to access your account. Verify now to keep it safe.",
    "Your refund is ready. Click here now to claim it before it expires today.",
]

LEGIT_TEMPLATES = [
    "Hi team, please find attached the meeting notes from yesterday's discussion.",
    "Reminder: our weekly sync is scheduled for tomorrow at 10 AM.",
    "Thanks for your email, I will get back to you by end of week.",
    "Please review the attached report and share your feedback when convenient.",
    "Here is the invoice for last month's services as discussed.",
    "The project deadline has been moved to next Friday, please plan accordingly.",
    "Attached is the presentation for tomorrow's client meeting.",
    "Happy birthday! Hope you have a wonderful day with family and friends.",
    "Your order has been shipped and will arrive within 5 business days.",
    "Thank you for subscribing to our monthly newsletter, here are this month's updates.",
    "Can we reschedule our call to Thursday afternoon instead of Wednesday?",
    "Please find the updated resume attached for your review.",
    "The library book you requested is now available for pickup.",
    "Our team completed the sprint successfully, details in the attached summary.",
    "Looking forward to catching up over coffee next week.",
]


def build(n_per_class=60, out_path="dataset.csv"):
    rows = []
    for _ in range(n_per_class):
        rows.append((random.choice(PHISHING_TEMPLATES), 1))
        rows.append((random.choice(LEGIT_TEMPLATES), 0))
    random.shuffle(rows)

    out_full = os.path.join(os.path.dirname(__file__), out_path)
    with open(out_full, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {out_full}")


if __name__ == "__main__":
    build()
