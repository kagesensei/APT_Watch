import io

WANNACRY_SHA256 = "3044416f2a33213a25eddda36cf89533d6edf2fed6ea018ee858238099e545de"


def _upload(client, text, filename="scan.txt"):
    return client.post(
        "/scan/upload",
        data={"file": (io.BytesIO(text.encode("utf-8")), filename)},
        content_type="multipart/form-data",
    )


class TestScanPage:
    def test_scan_index_renders(self, client):
        assert client.get("/scan/").status_code == 200


class TestScanUpload:
    def test_no_file_is_a_400(self, client):
        resp = client.post("/scan/upload", data={}, content_type="multipart/form-data")
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_known_hash_is_reported_as_matched(self, client):
        resp = _upload(client, f"suspicious file hash: {WANNACRY_SHA256}\n")
        assert resp.status_code == 200
        payload = resp.get_json()
        assert payload["total_indicators_found"] == 1
        assert payload["results"][0]["matched"] is True
        assert payload["results"][0]["type"] == "hash"

    def test_unknown_indicators_are_reported_as_not_matched(self, client):
        resp = _upload(client, "beacon to 203.0.113.99 and http://not-a-real-indicator.example/x\n")
        payload = resp.get_json()
        assert payload["total_indicators_found"] == 2
        assert all(r["matched"] is False for r in payload["results"])

    def test_empty_file_reports_zero_indicators(self, client):
        resp = _upload(client, "nothing interesting here")
        payload = resp.get_json()
        assert payload["total_indicators_found"] == 0
        assert payload["results"] == []

    def test_binary_garbage_file_is_rejected(self, client):
        resp = client.post(
            "/scan/upload",
            data={"file": (io.BytesIO(bytes(range(256)) * 20), "garbage.bin")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400
        assert "doesn't look like a text file" in resp.get_json()["error"]
