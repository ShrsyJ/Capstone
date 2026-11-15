import sys
import unittest
from pathlib import Path

EVAL = Path(__file__).resolve().parents[1] / "eval"
sys.path.insert(0, str(EVAL))

import json  # noqa: E402
import tempfile  # noqa: E402

from fake_secrets import FAKE_SECRETS, materialize  # noqa: E402
from hookguard.secrets import SecretScanner  # noqa: E402
from hookguard.models import Finding, Severity  # noqa: E402
from run_eval import load_cases, strict_hit  # noqa: E402


class FakeSecretTests(unittest.TestCase):
    def test_tokens_are_replaced(self):
        out = materialize('k = "__HG_FAKE_AWS_KEY_ID__"')
        self.assertEqual(out, f'k = "{FAKE_SECRETS["AWS_KEY_ID"]}"')

    def test_unknown_token_fails_loudly(self):
        with self.assertRaises(KeyError):
            materialize("__HG_FAKE_NOPE__")

    def test_case_files_hold_no_raw_secrets_but_materialized_ones_are_detected(self):
        scanner = SecretScanner()
        for name in ("p01_aws_key.py", "p02_db_url.py", "p03_generic_password.js"):
            raw = (EVAL / "cases" / name).read_text("utf-8")
            raw_hits = [f for i, l in enumerate(raw.splitlines()) for f in scanner.scan_text(name, i + 1, l)]
            self.assertEqual(raw_hits, [], f"{name} contains a literal secret")
            real = materialize(raw)
            hits = [f for i, l in enumerate(real.splitlines()) for f in scanner.scan_text(name, i + 1, l)]
            self.assertTrue(hits, f"{name} should trigger the scanner once materialized")


class SplitTests(unittest.TestCase):
    def test_load_cases_filters_by_split(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            for n in ("a.py", "b.py", "c.py"):
                (d / n).write_text("x = 1\n")
            labels = {"_comment": "x", "a.py": {"block": False, "split": "dev"},
                      "b.py": {"block": True, "split": "test"}, "c.py": {"block": False}}
            (d / "labels.json").write_text(json.dumps(labels))
            names = lambda split: [c[0] for c in load_cases(d, d / "labels.json", split)]  # noqa: E731
            self.assertEqual(names("dev"), ["a.py", "c.py"])  # missing split defaults to dev
            self.assertEqual(names("test"), ["b.py"])
            self.assertEqual(names("all"), ["a.py", "b.py", "c.py"])

    def test_seed_cases_are_all_dev(self):
        labels = json.loads((EVAL / "labels.json").read_text())
        self.assertTrue(all(v["split"] == "dev" for k, v in labels.items() if not k.startswith("_")))


class StrictHitTests(unittest.TestCase):
    label = {"block": True, "category": "auth", "also": ["crypto"], "lines": [4, 5]}

    def f(self, line, category, sev=Severity.HIGH):
        return Finding(file="x.py", line=line, severity=sev, category=category, rule="r", message="m", source="llm")

    def test_right_category_and_line(self):
        self.assertTrue(strict_hit([self.f(4, "auth")], self.label, Severity.HIGH))
        self.assertTrue(strict_hit([self.f(5, "crypto")], self.label, Severity.HIGH))  # accepted alternative

    def test_wrong_category_line_or_severity_is_not_a_hit(self):
        self.assertFalse(strict_hit([self.f(4, "injection")], self.label, Severity.HIGH))
        self.assertFalse(strict_hit([self.f(2, "auth")], self.label, Severity.HIGH))
        self.assertFalse(strict_hit([self.f(4, "auth", Severity.MEDIUM)], self.label, Severity.HIGH))

    def test_static_categories_are_mapped(self):
        label = {"block": True, "category": "injection", "lines": [2]}
        self.assertTrue(strict_hit([self.f(2, "sql-injection")], label, Severity.HIGH))


if __name__ == "__main__":
    unittest.main()
