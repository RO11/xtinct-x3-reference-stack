from __future__ import annotations

import hashlib
import http.client
import json
import threading
import unittest
from urllib.parse import quote

import network_fixture
import server
import compile_firmware_contract_gate
import verify_network_contract_parity


class CorpusContractTests(unittest.TestCase):
    def test_simulator_is_source_bound_to_current_firmware_contracts(self) -> None:
        verify_network_contract_parity.verify()

    def test_actual_firmware_constexpr_network_policies_compile_for_esp32c3(self) -> None:
        compile_firmware_contract_gate.verify()

    def test_v1_corpus_stays_inside_firmware_bounds(self) -> None:
        corpus = network_fixture.CORPUS
        self.assertLessEqual(len(corpus.manifest_body), 8 * 1024)
        self.assertEqual(1, corpus.manifest["schema"])
        self.assertEqual(set(network_fixture.V1_TASK_IDS), {card["id"] for card in corpus.manifest["cards"]})
        for reference in corpus.manifest["cards"]:
            self.assertRegex(reference["revision"], r"^[0-9a-f]{32}$")
            self.assertEqual(f"/v1/cards/{reference['id']}.json", reference["url"])
            card_body = corpus.cards[reference["id"]]
            self.assertLessEqual(len(card_body), 16 * 1024)
            card = json.loads(card_body)
            report = corpus.reports[(reference["id"], reference["revision"])]
            self.assertLessEqual(len(report), 24 * 1024)
            self.assertEqual(len(report), card["report"]["bytes"])
            self.assertEqual(hashlib.sha256(report).hexdigest(), card["report"]["sha256"])

    def test_v2_corpus_stays_inside_delivery_and_digest_bounds(self) -> None:
        corpus = network_fixture.CORPUS
        self.assertEqual(18, len(corpus.changes))
        for change in corpus.changes:
            if "delivery" not in change:
                continue
            delivery = change["delivery"]
            artifact = corpus.artifacts[delivery["sha256"]]
            self.assertLessEqual(len(delivery["title"].encode("utf-8")), 120)
            self.assertEqual(len(artifact), delivery["bytes"])
            self.assertEqual(hashlib.sha256(artifact).hexdigest(), delivery["sha256"])
            digest = delivery["metadata"]["digest"]
            self.assertLessEqual(len(digest["summary"].encode("utf-8")), 144)
            self.assertLessEqual(len(digest["points"]), 2)
            self.assertTrue(all(len(point.encode("utf-8")) <= 64 for point in digest["points"]))


class NetworkEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.store = server.SessionStore()
        cls.httpd = server.X3SimulatorHTTPServer((server.LOOPBACK_HOST, 0), cls.store)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)
        cls.store.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        cookie: str | None = None,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection(server.LOOPBACK_HOST, self.port, timeout=3)
        request_headers = dict(headers or {})
        if cookie:
            request_headers["Cookie"] = cookie
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        response_body = response.read()
        response_headers = {name.lower(): value for name, value in response.getheaders()}
        connection.close()
        return response.status, response_headers, response_body

    @staticmethod
    def auth(accept: str = "application/json") -> dict[str, str]:
        return {"Authorization": "Bearer " + "synthetic-read-token", "Accept": accept}

    def select(self, scenario: str) -> str:
        body = json.dumps({"scenario": scenario}).encode("utf-8")
        status, headers, response = self.request(
            "POST",
            "/api/network/scenario",
            headers={"Content-Type": "application/json"},
            body=body,
        )
        self.assertEqual(200, status, response)
        self.assertEqual(scenario, json.loads(response)["scenario"])
        return headers["set-cookie"].split(";", 1)[0]

    def test_scenario_catalog_is_explicitly_local_and_nonproduction(self) -> None:
        status, _, body = self.request("GET", "/api/network/scenarios")
        self.assertEqual(200, status)
        catalog = json.loads(body)
        self.assertFalse(catalog["production_access"])
        self.assertEqual("localhost-http", catalog["transport"])
        self.assertEqual(set(network_fixture.SCENARIOS), {scenario["id"] for scenario in catalog["scenarios"]})

    def test_v1_uses_bearer_auth_revision_pinning_and_conditional_get(self) -> None:
        cookie = self.select("cache-current")
        status, _, _ = self.request("GET", "/mock/v1/manifest.json", cookie=cookie)
        self.assertEqual(401, status)

        status, headers, body = self.request(
            "GET", "/mock/v1/manifest.json", cookie=cookie, headers=self.auth()
        )
        self.assertEqual(200, status)
        manifest = json.loads(body)
        self.assertEqual(manifest["etag"], headers["etag"])
        self.assertEqual(str(len(body)), headers["content-length"])

        status, headers, body = self.request(
            "GET",
            "/mock/v1/manifest.json",
            cookie=cookie,
            headers={**self.auth(), "If-None-Match": manifest["etag"]},
        )
        self.assertEqual(304, status)
        self.assertEqual(b"", body)
        self.assertEqual(manifest["etag"], headers["etag"])

        for reference in manifest["cards"]:
            path = f"/mock{reference['url']}?revision={reference['revision']}"
            status, _, card_body = self.request("GET", path, cookie=cookie, headers=self.auth())
            self.assertEqual(200, status)
            card = json.loads(card_body)
            self.assertEqual(reference["revision"], card["revision"])
            report_path = f"/mock{card['report']['url']}"
            status, _, report = self.request(
                "GET", report_path, cookie=cookie, headers=self.auth("text/plain; charset=utf-8")
            )
            self.assertEqual(200, status)
            self.assertEqual(card["report"]["bytes"], len(report))
            self.assertEqual(card["report"]["sha256"], hashlib.sha256(report).hexdigest())

        first = manifest["cards"][0]
        status, _, _ = self.request(
            "GET", f"/mock{first['url']}?revision={'0' * 32}", cookie=cookie, headers=self.auth()
        )
        self.assertEqual(404, status)

    def test_v2_pages_exactly_eight_changes_and_serves_integrity_headers(self) -> None:
        cookie = self.select("pagination")
        cursor = "0"
        page_sizes: list[int] = []
        first_delivery: dict[str, object] | None = None
        while True:
            status, _, body = self.request(
                "GET",
                f"/mock/v2/sync?cursor={cursor}&limit=8",
                cookie=cookie,
                headers=self.auth(),
            )
            self.assertEqual(200, status)
            page = json.loads(body)
            page_sizes.append(len(page["deliveries"]) + len(page["tombstones"]))
            if first_delivery is None and page["deliveries"]:
                first_delivery = page["deliveries"][0]
            cursor = page["cursor"]
            if not page["has_more"]:
                break
        self.assertEqual([8, 8, 2], page_sizes)
        self.assertEqual("18", cursor)
        self.assertIsNotNone(first_delivery)
        assert first_delivery is not None
        digest = str(first_delivery["sha256"])
        status, headers, artifact = self.request(
            "GET",
            f"/mock/v2/artifacts/{quote(digest)}",
            cookie=cookie,
            headers=self.auth(str(first_delivery["mime"])),
        )
        self.assertEqual(200, status)
        self.assertEqual(str(first_delivery["mime"]), headers["content-type"])
        self.assertEqual(f'"{digest}"', headers["etag"])
        self.assertEqual("nosniff", headers["x-content-type-options"])
        self.assertEqual(str(len(artifact)), headers["content-length"])
        self.assertEqual(digest, hashlib.sha256(artifact).hexdigest())

    def test_ack_failure_retains_batch_then_accepts_and_deduplicates_retry(self) -> None:
        cookie = self.select("ack-failure-once")
        event = {
            "event_id": "sim-x3-main-1786492800-1",
            "item_id": "sim-today",
            "revision": "a" * 64,
            "type": "opened",
            "occurred_at": "2026-08-12T08:00:00Z",
            "data": {},
        }
        payload = json.dumps({"schema": 2, "events": [event]}, separators=(",", ":")).encode("utf-8")
        ack_headers = {**self.auth(), "Content-Type": "application/json"}
        status, _, _ = self.request(
            "POST", "/mock/v2/acks", cookie=cookie, headers=ack_headers, body=payload
        )
        self.assertEqual(503, status)
        status, _, body = self.request(
            "POST", "/mock/v2/acks", cookie=cookie, headers=ack_headers, body=payload
        )
        self.assertEqual(200, status)
        self.assertEqual(1, json.loads(body)["accepted"])
        status, _, body = self.request(
            "POST", "/mock/v2/acks", cookie=cookie, headers=ack_headers, body=payload
        )
        self.assertEqual(200, status)
        self.assertEqual(1, json.loads(body)["duplicates"])

    def test_injected_http_and_malformed_failures_are_observable_in_status(self) -> None:
        cookie = self.select("http-503")
        status, _, _ = self.request(
            "GET", "/mock/v2/sync?cursor=0&limit=8", cookie=cookie, headers=self.auth()
        )
        self.assertEqual(503, status)
        status, _, body = self.request("GET", "/api/network/status", cookie=cookie)
        self.assertEqual(200, status)
        snapshot = json.loads(body)
        self.assertEqual(1, snapshot["request_counts"]["GET /v2/sync"])
        self.assertEqual("disabled", snapshot["outbound_network"])

        cookie = self.select("malformed-payload")
        status, _, body = self.request(
            "GET", "/mock/v2/sync?cursor=0&limit=8", cookie=cookie, headers=self.auth()
        )
        self.assertEqual(200, status)
        self.assertEqual("BAD/DEVICE", json.loads(body)["device_id"])


if __name__ == "__main__":
    unittest.main()
