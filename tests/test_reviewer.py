import copy
import tempfile
import unittest
from pathlib import Path

import fakes
from hookguard.config import DEFAULTS
from hookguard.diff import file_as_change
from hookguard.engine import run_pipeline
from hookguard.llm import Backend, LLMError
from hookguard.models import Severity
from hookguard.reviewer import LLMReviewer, parse_model_json, render_patch


class ScriptedBackend(Backend):
    name = "scripted"

    def __init__(self, replies):
        super().__init__(model="scripted")
        self.replies = list(replies)
        self.prompts = []

    def chat(self, system, user):
        self.prompts.append(user)
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    def health(self):
        return True, "ok"


def cfg(**llm):
    c = copy.deepcopy(DEFAULTS)
    c["llm"].update({"cache": False, **llm})
    return c


class ParseTests(unittest.TestCase):
    def test_plain_wrapped_and_fenced(self):
        self.assertEqual(parse_model_json('{"findings": [{"line": 1}]}'), [{"line": 1}])
        self.assertEqual(parse_model_json('Sure! {"findings": []} hope this helps'), [])
        self.assertEqual(parse_model_json('```json\n[{"line": 2}]\n```'), [{"line": 2}])
        with self.assertRaises(LLMError):
            parse_model_json("no json here")


class ReviewerTests(unittest.TestCase):
    def setUp(self):
        self.change = file_as_change("svc.py", "def h(req):\n    path = req.args['p']\n    return open(path).read()\n")

    def test_render_patch_numbers_lines_and_masks_secrets(self):
        ch = file_as_change("a.py", f'x = 1\nk = "{fakes.AWS_KEY_ID}"\n')
        out = "\n".join(render_patch(ch))
        self.assertIn("    1 + x = 1", out)
        self.assertNotIn(fakes.AWS_KEY_ID_TAIL, out)

    def test_valid_finding_is_kept_and_hallucination_dropped(self):
        backend = ScriptedBackend([
            '{"findings": ['
            '{"line": 3, "severity": "high", "category": "path-traversal", "message": "user path"},'
            '{"line": 40, "severity": "critical", "category": "secret", "message": "invented"},'
            '{"line": 1, "severity": "low", "category": "style", "message": "naming"}]}'
        ])
        res = LLMReviewer(backend, cfg()["llm"], progress=False).review([self.change])
        self.assertEqual([(f.line, f.category) for f in res.findings], [(3, "path-traversal")])
        self.assertEqual(res.stats.dropped_invalid, 1)

    def test_off_by_one_line_is_snapped(self):
        ch = file_as_change("a.py", "\n".join(["x = 1"] * 10))
        ch.added = [a for a in ch.added if a.lineno == 5]  # only line 5 was "added"
        backend = ScriptedBackend(['{"findings": [{"line": 6, "severity": "high", "category": "auth", "message": "m"}]}'])
        res = LLMReviewer(backend, cfg()["llm"], progress=False).review([ch])
        self.assertEqual(res.findings[0].line, 5)

    def test_cache_avoids_second_call(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cache.json"
            reply = '{"findings": []}'
            b1 = ScriptedBackend([reply])
            LLMReviewer(b1, cfg(cache=True)["llm"], cache_path=path, progress=False).review([self.change])
            b2 = ScriptedBackend([])  # would raise IndexError if called
            res = LLMReviewer(b2, cfg(cache=True)["llm"], cache_path=path, progress=False).review([self.change])
            self.assertEqual(res.stats.cached, 1)
            self.assertEqual(b2.prompts, [])


class ThinkOptionTests(unittest.TestCase):
    def _payload(self, think):
        from fake_llm import FakeOllama
        from hookguard.llm import make_backend
        with FakeOllama() as fake:
            make_backend({"backend": "ollama", "model": "fake-model", "host": fake.url, "think": think}).chat("s", "u")
            return fake.requests[0]

    def test_usage_is_captured_from_ollama(self):
        from fake_llm import FakeOllama
        with FakeOllama() as fake:
            rep = run_pipeline([file_as_change("a.py", "x = 1\n")], cfg(host=fake.url, model="fake-model"),
                               progress=False)
        self.assertEqual(rep.llm_usage, [{"tokens_in": 120, "tokens_out": 8, "load_s": 0.0,
                                          "prompt_s": 0.2, "gen_s": 0.1}])

    def test_think_is_off_by_default(self):
        from hookguard.llm import make_backend
        self.assertIs(make_backend(DEFAULTS["llm"]).think, False)

    def test_think_auto_is_not_sent(self):
        self.assertNotIn("think", self._payload("auto"))

    def test_think_false_is_sent(self):
        self.assertIs(self._payload(False)["think"], False)
        self.assertIs(self._payload("false")["think"], False)


class UnavailableTests(unittest.TestCase):
    def test_missing_model_stops_after_one_request_with_pull_hint(self):
        from fake_llm import FakeOllama
        with FakeOllama() as fake:
            c = cfg(host=fake.url, model="missing-model")
            files = [file_as_change(f"f{i}.py", "x = 1\n") for i in range(3)]
            rep = run_pipeline(files, c, progress=False)
            self.assertEqual(len(fake.requests), 1)
            llm_warnings = [w for w in rep.warnings if w.startswith("LLM:")]
            self.assertEqual(len(llm_warnings), 1)
            self.assertIn("ollama pull missing-model", llm_warnings[0])
            self.assertFalse(rep.blocked)  # fail open by default


class PipelineTests(unittest.TestCase):
    def test_server_down_fails_open_by_default(self):
        c = cfg(host="http://127.0.0.1:9", timeout=2)  # nothing listens on port 9
        rep = run_pipeline([file_as_change("a.py", "x = 1\n")], c, progress=False)
        self.assertFalse(rep.blocked)
        self.assertTrue(any("cannot reach" in w for w in rep.warnings))

    def test_server_down_fails_closed_when_configured(self):
        c = cfg(host="http://127.0.0.1:9", timeout=2, on_error="block")
        rep = run_pipeline([file_as_change("a.py", "x = 1\n")], c, progress=False)
        self.assertTrue(rep.blocked)

    def test_secret_blocks_without_llm(self):
        rep = run_pipeline([file_as_change("a.py", f'K = "{fakes.AWS_KEY_ID}"\n')], cfg(), use_llm=False)
        self.assertTrue(rep.blocked)
        self.assertEqual(rep.findings[0].severity, Severity.CRITICAL)

    def test_prose_files_are_secret_scanned_but_not_sent_to_the_model(self):
        from fake_llm import FakeOllama
        with FakeOllama() as fake:
            c = cfg(host=fake.url, model="fake-model")
            doc = file_as_change("NOTES.md", "Calling danger(x) is an injection risk.\n")
            code = file_as_change("a.py", "x = 1\n")
            rep = run_pipeline([doc, code], c, progress=False)
            self.assertEqual(len(fake.requests), 1)
            self.assertNotIn("NOTES.md", fake.requests[0]["messages"][-1]["content"])
            self.assertFalse(rep.blocked)
        leak = file_as_change("README.md", f'Use key {fakes.AWS_KEY_ID} to start\n')
        self.assertTrue(run_pipeline([leak], cfg(), use_llm=False).blocked)

    def test_excluded_files_are_skipped(self):
        rep = run_pipeline([file_as_change("package-lock.json", f'"k": "{fakes.AWS_KEY_ID}"')], cfg(), use_llm=False)
        self.assertFalse(rep.blocked)
        self.assertEqual(rep.files_skipped, ["package-lock.json"])


if __name__ == "__main__":
    unittest.main()
