import os
import pytest


def test_scan_upload_and_report_pipeline(client, auth_headers):
    eml_path = "samples/test_phishing.eml"
    assert os.path.exists(eml_path), f"Sample file not found: {eml_path}"

    # 1. Upload scan
    with open(eml_path, "rb") as f:
        upload_res = client.post(
            "/api/scans/upload",
            files={"file": ("test_phishing.eml", f, "message/rfc822")},
            headers=auth_headers,
        )
    assert upload_res.status_code == 201, f"Upload error: {upload_res.text}"
    scan = upload_res.json()
    assert scan["id"] > 0
    assert scan["scan_status"] == "completed"
    assert scan["overall_risk"] in ["Critical Risk", "High Risk", "Medium Risk", "Low Risk"]
    assert len(scan["findings"]) > 0
    scan_id = scan["id"]

    # 2. Get scan details
    detail_res = client.get(f"/api/scans/{scan_id}", headers=auth_headers)
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == scan_id
    assert detail["subject"] is not None

    # 3. Get findings endpoint
    findings_res = client.get(f"/api/scans/{scan_id}/findings", headers=auth_headers)
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert isinstance(findings, list)

    # 4. Download PDF forensic report
    report_res = client.get(f"/api/scans/{scan_id}/report", headers=auth_headers)
    assert report_res.status_code == 200
    assert report_res.headers["content-type"] == "application/pdf"
    assert len(report_res.content) > 1000  # PDF generated with content


def test_analyze_raw_source(client, auth_headers):
    raw_email = (
        "From: alerts@paypal-verification.xyz\n"
        "To: victim@example.com\n"
        "Subject: Urgent: Verify your PayPal account\n"
        "Date: Tue, 15 Oct 2026 10:00:00 +0000\n\n"
        "Dear Customer, your PayPal account has been suspended. "
        "Click here: http://198.51.100.12/verify to update your billing information immediately."
    )

    res = client.post("/api/scans/analyze-source", json={"raw_email": raw_email}, headers=auth_headers)
    assert res.status_code == 201
    scan = res.json()
    assert scan["id"] > 0
    assert scan["overall_risk"] in ["Critical Risk", "High Risk", "Medium Risk"]
    # Check that IP URL was extracted
    assert any(u["is_ip_address"] for u in scan["extracted_urls"])


def test_list_scans(client, auth_headers):
    res = client.get("/api/scans?page=1&page_size=10", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "items" in data
    assert isinstance(data["items"], list)
