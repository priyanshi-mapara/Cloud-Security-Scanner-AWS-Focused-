from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_scan_file_endpoint():
    response = client.post(
        "/scan/file", json={"path": "sample_data/s3_bucket_public.json"}
    )
    assert response.status_code == 200
    assert response.json()["result"]["summary"]["total_findings"] == 4


def test_scan_directory_and_get_summary_endpoints():
    scan_response = client.post("/scan/directory", json={"path": "sample_data"})
    assert scan_response.status_code == 200

    findings_response = client.get("/findings")
    summary_response = client.get("/summary")
    assert findings_response.status_code == 200
    assert summary_response.status_code == 200
    assert summary_response.json()["summary"]["total_findings"] == len(
        findings_response.json()["findings"]
    )
