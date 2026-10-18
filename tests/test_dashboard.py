import pytest


def test_dashboard_summary(client, auth_headers):
    res = client.get("/api/dashboard/summary", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "total_scans" in data
    assert "likely_phishing" in data
    assert "suspicious" in data
    assert "likely_legitimate" in data
    assert "model_status" in data
    assert data["model_status"] == "loaded"


def test_dashboard_trends(client, auth_headers):
    res = client.get("/api/dashboard/trends?days=30", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "period_days" in data
    assert "data" in data
    assert isinstance(data["data"], list)


def test_model_endpoints(client, auth_headers):
    status_res = client.get("/api/model/status", headers=auth_headers)
    assert status_res.status_code == 200
    assert status_res.json()["status"] == "loaded"

    metrics_res = client.get("/api/model/metrics", headers=auth_headers)
    assert metrics_res.status_code == 200
