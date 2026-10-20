"""API endpoint + validation tests (in-memory Mongo via mongomock)."""


def test_home_ok(app_client):
    r = app_client.get("/")
    assert r.status_code == 200
    assert "SOCShield" in r.get_json()["message"]


def test_health(app_client):
    assert app_client.get("/health").get_json()["status"] == "ok"


def test_ingest_rejects_non_json(app_client):
    r = app_client.post("/ingest", data="not json",
                        content_type="application/json")
    assert r.status_code == 400


def test_block_ip_validates(app_client):
    r = app_client.post("/block-ip", json={"ip": "not-an-ip"})
    assert r.status_code == 400


def test_block_ip_missing(app_client):
    r = app_client.post("/block-ip", json={})
    assert r.status_code == 400


def test_resolve_alert_invalid_id(app_client):
    r = app_client.post("/resolve-alert", json={"id": "nope"})
    assert r.status_code == 400


def test_assign_alert_missing_data(app_client):
    r = app_client.post("/assign-alert", json={"id": "x"})
    assert r.status_code == 400


def test_ip_intel_rejects_bad_ip(app_client):
    r = app_client.get("/ip-intel/not-an-ip")
    assert r.status_code == 400


def test_stats_shape(app_client):
    r = app_client.get("/stats")
    assert r.status_code == 200
    body = r.get_json()
    for key in ("total_logs", "total_alerts", "open_alerts",
                "critical_alerts", "severity_distribution"):
        assert key in body


def test_upload_pcap_rejects_bad_extension(app_client):
    import io
    data = {"file": (io.BytesIO(b"x"), "evil.txt")}
    r = app_client.post("/upload-pcap", data=data,
                        content_type="multipart/form-data")
    assert r.status_code == 400
