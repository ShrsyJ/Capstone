import sys
import unittest
from pathlib import Path

EVAL = Path(__file__).resolve().parents[1] / "eval"
sys.path.insert(0, str(EVAL))

from fake_secrets import FAKE_SECRETS, materialize  # noqa: E402
from hookguard.secrets import SecretScanner  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
