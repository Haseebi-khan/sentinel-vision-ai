import json
import os
import sys
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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


CFG = {"provider": "anthropic", "style": "anthropic", "url": "", "model": "test-model", "key": "k", "timeout": 5}


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
        out = v.analyze(EVENT, loader=fake_loader, caller=fake_caller(GOOD), cfg=CFG)
        self.assertEqual(out["analysis_status"], "completed")

    def test_garbage_reply_is_unavailable(self):
        out = v.analyze(EVENT, loader=fake_loader, caller=fake_caller("nope"), cfg=CFG)
        self.assertEqual(out["analysis_status"], "unavailable")

    def test_missing_key_is_unavailable(self):
        saved = {k: os.environ.pop(k, None) for k in ("VLM_API_KEY", "VLM_PROVIDER")}
        try:
            out = v.analyze(EVENT, loader=fake_loader, caller=fake_caller(GOOD))
        finally:
            for k, val in saved.items():
                if val is not None:
                    os.environ[k] = val
        self.assertEqual(out["analysis_status"], "unavailable")
        self.assertIn("VLM_API_KEY", out["reason"])

    def test_unexpected_exception_is_unavailable(self):
        def boom(*a):
            raise RuntimeError("x")
        out = v.analyze(EVENT, loader=fake_loader, caller=boom, cfg=CFG)
        self.assertEqual(out["analysis_status"], "unavailable")

    def test_no_snapshot(self):
        ev = {k: val for k, val in EVENT.items() if k != "snapshot_url"}
        self.assertEqual(v.analyze(ev, cfg=CFG)["analysis_status"], "unavailable")


class NormalizeTests(unittest.TestCase):
    FLAT = {"event_id": "e1", "camera_id": "door", "label": "person", "confidence": 0.9,
            "recognized": False, "person_name": "unknown", "plate_text": "AB12", "plate_confidence": 0.8,
            "snapshot_url": "http://frigate.local/s.jpg"}

    def test_nested_passthrough(self):
        self.assertIs(v.normalize_event(EVENT), EVENT)

    def test_body_wrapper(self):
        self.assertEqual(v.normalize_event({"body": EVENT})["detection"]["label"], "person")

    def test_flat_event_from_workflow(self):
        out = v.normalize_event({"valid": True, "event": self.FLAT})
        self.assertEqual(out["detection"]["label"], "person")
        self.assertIs(out["biometrics"]["recognized"], False)
        self.assertEqual(out["alpr"]["plate_text"], "AB12")
        self.assertEqual(v.build_context(out)["detected_label"], "person")

    def test_flat_resident_is_skipped(self):
        flat = dict(self.FLAT, recognized=True, person_name="Ali")
        out = v.analyze({"event": flat}, cfg=CFG)
        self.assertEqual(out["model"], "local-rule")


class ResidentTests(unittest.TestCase):
    RESIDENT = dict(EVENT, biometrics={"recognized": True, "person_name": "Ali"})

    def test_recognised_resident_skips_model(self):
        def must_not_call(*a):
            raise AssertionError("model was called")
        out = v.analyze(self.RESIDENT, loader=must_not_call, caller=must_not_call, cfg=CFG)
        self.assertEqual(out["threat_score"], 10)
        self.assertFalse(out["requires_human_review"])
        self.assertEqual(out["model"], "local-rule")

    def test_unknown_name_is_not_a_resident(self):
        ev = dict(EVENT, biometrics={"recognized": True, "person_name": "unknown"})
        self.assertIsNone(v.recognized_resident(ev))

    def test_vehicle_never_skipped(self):
        ev = dict(self.RESIDENT, detection=dict(EVENT["detection"], label="car"))
        self.assertIsNone(v.recognized_resident(ev))

    def test_can_be_switched_off(self):
        os.environ["VLM_SKIP_RECOGNIZED"] = "0"
        try:
            self.assertIsNone(v.recognized_resident(self.RESIDENT))
        finally:
            del os.environ["VLM_SKIP_RECOGNIZED"]


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.saved = {k: os.environ.pop(k, None) for k in
                      ("VLM_PROVIDER", "VLM_API_KEY", "VLM_MODEL", "VLM_API_URL")}

    def tearDown(self):
        for k, val in self.saved.items():
            os.environ.pop(k, None)
            if val is not None:
                os.environ[k] = val

    def test_default_needs_key(self):
        with self.assertRaises(v.AnalyzerError):
            v.get_config()

    def test_anthropic_defaults(self):
        os.environ["VLM_API_KEY"] = "k"
        cfg = v.get_config()
        self.assertEqual(cfg["provider"], "anthropic")
        self.assertTrue(cfg["model"])

    def test_openai_needs_model_but_not_key(self):
        os.environ["VLM_PROVIDER"] = "openai"
        with self.assertRaises(v.AnalyzerError):
            v.get_config()
        os.environ["VLM_MODEL"] = "llava"
        self.assertEqual(v.get_config()["key"], "")

    def test_gemini_preset(self):
        os.environ["VLM_PROVIDER"] = "gemini"
        with self.assertRaises(v.AnalyzerError):      # key and model both required
            v.get_config()
        os.environ["VLM_API_KEY"] = "k"
        with self.assertRaises(v.AnalyzerError):
            v.get_config()
        os.environ["VLM_MODEL"] = "some-gemini-model"
        cfg = v.get_config()
        self.assertEqual(cfg["style"], "openai")
        self.assertIn("generativelanguage.googleapis.com", cfg["url"])

    def test_unknown_provider(self):
        os.environ["VLM_PROVIDER"] = "nope"
        with self.assertRaises(v.AnalyzerError):
            v.get_config()


class FakeModelServer(BaseHTTPRequestHandler):
    seen = {}

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        FakeModelServer.seen = {"path": self.path, "headers": {k.lower(): val for k, val in self.headers.items()}, "body": body}
        if self.path == "/v1/messages":
            reply = {"content": [{"type": "text", "text": json.dumps(GOOD)}]}
        else:
            reply = {"choices": [{"message": {"content": json.dumps(GOOD)}}]}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class ProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeModelServer)
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def run_provider(self, cfg):
        return v.analyze(EVENT, loader=fake_loader, cfg=cfg)

    def test_anthropic_request_shape(self):
        out = self.run_provider(dict(CFG, url=self.base + "/v1/messages"))
        self.assertEqual(out["analysis_status"], "completed")
        seen = FakeModelServer.seen
        self.assertEqual(seen["headers"]["x-api-key"], "k")
        block = seen["body"]["messages"][0]["content"][0]
        self.assertEqual(block["source"]["type"], "base64")

    def test_openai_request_shape_without_key(self):
        cfg = {"provider": "openai", "style": "openai", "url": self.base + "/v1/chat/completions",
               "model": "llava", "key": "", "timeout": 5}
        out = self.run_provider(cfg)
        self.assertEqual(out["analysis_status"], "completed")
        self.assertEqual(out["model"], "llava")
        seen = FakeModelServer.seen
        self.assertNotIn("authorization", {k.lower() for k in seen["headers"]})
        image = seen["body"]["messages"][1]["content"][1]["image_url"]["url"]
        self.assertTrue(image.startswith("data:image/jpeg;base64,"))

    def test_openai_sends_bearer_key(self):
        cfg = {"provider": "openai", "style": "openai", "url": self.base + "/v1/chat/completions",
               "model": "m", "key": "secret", "timeout": 5}
        self.run_provider(cfg)
        self.assertEqual(FakeModelServer.seen["headers"]["authorization"], "Bearer secret")

    def test_reasoning_effort_is_sent_when_set(self):
        cfg = {"provider": "gemini", "style": "openai", "url": self.base + "/v1/chat/completions",
               "model": "m", "key": "k", "timeout": 5, "reasoning_effort": "low"}
        self.run_provider(cfg)
        self.assertEqual(FakeModelServer.seen["body"]["reasoning_effort"], "low")

    def test_reasoning_effort_omitted_by_default(self):
        cfg = {"provider": "openai", "style": "openai", "url": self.base + "/v1/chat/completions",
               "model": "m", "key": "", "timeout": 5}
        self.run_provider(cfg)
        self.assertNotIn("reasoning_effort", FakeModelServer.seen["body"])

    def test_dead_server_is_unavailable(self):
        out = self.run_provider(dict(CFG, url="http://127.0.0.1:1/x"))
        self.assertEqual(out["analysis_status"], "unavailable")


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
