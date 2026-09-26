# AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

A college mini project that analyzes a suspicious email (`.eml`/`.txt`), scores it for
phishing risk, traces its delivery route on a map, and generates a downloadable PDF
forensic report.

## Features
- **Content analysis (ML):** TF-IDF + Logistic Regression / Random Forest, trained on a
  labeled phishing/legitimate dataset.
- **Header analysis:** SPF/DKIM/DMARC checks, From vs Reply-To/Return-Path mismatches,
  free-mail brand impersonation, lookalike domains.
- **URL analysis:** IP-based links, shorteners, "@" tricks, anchor-text mismatches,
  suspicious TLDs, punycode, lookalike domains, optional VirusTotal lookup.
- **Attachment analysis:** risky extensions, macro-enabled Office files, double
  extensions, hash lookups — attachments are never opened or executed.
- **Geolocation:** traces the email's `Received` header chain and plots hops on a map.
- **Weighted threat scoring:** combines all checks into one 0–100 score and verdict
  (Safe / Suspicious / Dangerous).
- **PDF forensic report:** cover page, metadata, evidence, route, score breakdown, and
  a SHA-256 chain-of-custody hash.
- **Web dashboard:** upload page, result page (gauge, chart, map), scan history.

## Tech stack
Flask · scikit-learn · pandas · SQLite · Leaflet.js · Chart.js · reportlab · Bootstrap 5

## Setup (Windows PowerShell)

```powershell
cd email-threat-detector
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file in the project root (optional keys can stay blank):
```
SECRET_KEY=some-random-string
VT_API_KEY=
```

Generate the starter dataset and train the model:
```powershell
python data\make_sample_dataset.py
python model\train_model.py
```
> The starter dataset is small and synthetic so the project runs out of the box.
> For your actual submission, replace `data/dataset.csv` with a real phishing/spam
> dataset from Kaggle (same columns: `text`, `label`), then re-run `train_model.py`.

Run the app:
```powershell
python app.py
```
Open **http://127.0.0.1:5000**

## Real-time inbox monitoring (optional)
Instead of manually uploading a file each time, the app can connect to a real
mailbox over IMAP and automatically scan every new email as it arrives.

1. Enable IMAP in your mailbox (Gmail: Settings -> Forwarding and POP/IMAP -> Enable IMAP).
2. Create an **App Password** - do NOT use your normal login password.
   Gmail: Google Account -> Security -> 2-Step Verification -> App Passwords.
3. Add these to your `.env` file:
   ```
   IMAP_HOST=imap.gmail.com
   IMAP_PORT=993
   IMAP_USER=youraddress@gmail.com
   IMAP_PASS=your-16-character-app-password
   POLL_INTERVAL_SECONDS=30
   ```
4. Run the app, open **Live Monitor** in the navbar, click **Start Monitoring**.
5. Send a test email to that mailbox and watch it appear in the live feed within
   `POLL_INTERVAL_SECONDS` seconds, fully scanned, no upload required.

This is real polling, not a simulation - every check (content, header, URL,
attachment, geolocation, scoring) runs live on the real incoming email, using
the exact same pipeline as a manual upload. It's not "instant push" like a
notification (that needs Gmail's Cloud Pub/Sub API, which is heavier setup than
a mini project needs) - it checks the inbox every `POLL_INTERVAL_SECONDS`, which
is the standard approach for lightweight real-time mail monitoring.

## Testing
```powershell
python test_suite_runner.py
```
Runs the full pipeline over the sample `.eml` files in `samples/` and prints an
accuracy summary. Add more files to `samples/test_suite/` (name them with "phish" or
"safe" in the filename) to expand the test set.

## Project structure
```
email-threat-detector/
  app.py                  Flask routes
  config.py                All weights, thresholds, lists
  modules/
    parser.py              Email parsing
    content_analysis.py    ML phishing-content check
    header_analysis.py     SPF/DKIM/DMARC + spoofing checks
    url_analysis.py        Link analysis
    attachment_analysis.py Attachment metadata checks
    geolocation.py          IP extraction + lookup
    scoring.py              Weighted final score
    database.py             SQLite scan history
    report.py               PDF report generation
  model/                    train_model.py + saved .pkl files
  data/                     dataset.csv + generator script
  templates/, static/       Web UI
  samples/                  Test .eml files
  test_suite_runner.py      Batch accuracy test
```

## Limitations
- Depends on the quality/age of the training dataset.
- IP geolocation is approximate — VPNs, proxies, and hosting providers can hide the
  real sender location.
- Free-tier APIs (ip-api.com, VirusTotal) have rate limits.
- Rule-based checks can be evaded by a sufficiently careful attacker.

## Future scope
- Deep learning models (e.g. BERT) for content analysis.
- Browser/Outlook plugin for real-time inbox scanning.
- Sandboxed attachment execution for dynamic analysis.

## Screenshots
_Add your own screenshots here before submission:_
- [ ] Upload page
- [ ] Result page (gauge + map)
- [ ] History page
- [ ] Sample PDF report page 1
- [ ] Model comparison chart (`static/img/model_comparison.png`)
