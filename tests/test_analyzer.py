import json
import os
import sys
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import vlm_analyzer as v  # noqa: E402

JPEG = b"\xff\xd8\xff\xe0" + b"0" * 32
EVENT = {
    "event_id": "evt-1",
    "timestamp": "2026-10-27T21:15:00Z",
    "camera_id": "front_door",
    "snapshot_url": "http://frigate.local/snap.jpg",
    "detection": {"label": "person", "confidence": 0.9, "bounding_box": [1, 2, 3, 4]},
    "biometrics": {"recognized": False, "person_name": "unknown"},
}
GOOD = {
    "threat_score": 45, "reason": "Unfamiliar person at the door.",
    "recommended_action": "request_human_review", "requires_human_review": True,
    "visible_evidence": ["person at door"], "image_quality": "good",
}


def fake_loader(ref):
    return "image/jpeg", "AAAA"


def fake_caller(reply):
    return lambda *a: reply if isinstance(reply, str) else json.dumps(reply)


class ParseTests(unittest.TestCase):
    def test_valid_reply(self):
        out = v.parse_analysis(json.dumps(GOOD))
        self.assertEqual(out["analysis_status"], "completed")
        self.assertEqual(out["threat_level"], "medium")

    def test_levels_match_n8n_thresholds(self):
        self.assertEqual(v.level_for(29), "low")
        self.assertEqual(v.level_for(30), "medium")
        self.assertEqual(v.level_for(69), "medium")
        self.assertEqual(v.level_for(70), "high")

    def test_json_inside_code_fence(self):
        out = v.parse_analysis("```json\n" + json.dumps(GOOD) + "\n```")
        self.assertEqual(out["threat_score"], 45)

    def test_rejects_bad_values(self):
        for patch in ({"threat_score": 101}, {"threat_score": -1}, {"threat_score": "high"},
                      {"threat_score": True}, {"reason": ""}, {"recommended_action": "call_police"},
                      {"requires_human_review": "yes"}):
            with self.assertRaises(v.AnalyzerError, msg=patch):
                v.parse_analysis(json.dumps({**GOOD, **patch}))

    def test_rejects_non_json(self):
        with self.assertRaises(v.AnalyzerError):
            v.parse_analysis("I cannot help with that.")

    def test_unusable_image_forces_review(self):
        reply = {**GOOD, "threat_score": 5, "recommended_action": "log_only",
                 "requires_human_review": False, "image_quality": "unusable"}
        out = v.parse_analysis(json.dumps(reply))
        self.assertTrue(out["requires_human_review"])
        self.assertEqual(out["recommended_action"], "request_human_review")


class AnalyzeTests(unittest.TestCase):
    def test_success(self):
        out = v.analyze(EVENT, loader=fake_loader, caller=fake_caller(GOOD), api_key="k")
        self.assertEqual(out["analysis_status"], "completed")

    def test_garbage_reply_is_unavailable(self):
        out = v.analyze(EVENT, loader=fake_loader, caller=fake_caller("nope"), api_key="k")
        self.assertEqual(out["analysis_status"], "unavailable")

    def test_missing_key_is_unavailable(self):
        old = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            out = v.analyze(EVENT, loader=fake_loader, caller=fake_caller(GOOD))
        finally:
            if old:
                os.environ["ANTHROPIC_API_KEY"] = old
        self.assertEqual(out["analysis_status"], "unavailable")

    def test_unexpected_exception_is_unavailable(self):
        def boom(*a):
            raise RuntimeError("x")
        out = v.analyze(EVENT, loader=fake_loader, caller=boom, api_key="k")
        self.assertEqual(out["analysis_status"], "unavailable")

    def test_no_snapshot(self):
        ev = {k: val for k, val in EVENT.items() if k != "snapshot_url"}
        self.assertEqual(v.analyze(ev, api_key="k")["analysis_status"], "unavailable")


class ImageTests(unittest.TestCase):
    def test_media_types(self):
        self.assertEqual(v.detect_media_type(JPEG), "image/jpeg")
        self.assertEqual(v.detect_media_type(b"\x89PNG\r\n\x1a\n0"), "image/png")
        with self.assertRaises(v.AnalyzerError):
            v.detect_media_type(b"<html>")

    def test_host_allowlist(self):
        with self.assertRaises(v.AnalyzerError):
            v.load_image("http://evil.example/x.jpg", allowed_hosts={"frigate.local"})

    def test_files_blocked_when_disallowed(self):
        with self.assertRaises(v.AnalyzerError):
            v.load_image("/etc/passwd", allow_files=False)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), v.make_handler("secret", set()))
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def post(self, body, token="secret"):
        req = urllib.request.Request(
            "http://127.0.0.1:%d/analyze" % self.port, data=body, method="POST",
            headers={"x-service-token": token} if token else {})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_requires_token(self):
        self.assertEqual(self.post(b"{}", token=None)[0], 401)

    def test_bad_json(self):
        self.assertEqual(self.post(b"not json")[0], 400)

    def test_disallowed_host_returns_unavailable(self):
        code, out = self.post(json.dumps({"body": EVENT}).encode())
        self.assertEqual(code, 200)
        self.assertEqual(out["analysis_status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
