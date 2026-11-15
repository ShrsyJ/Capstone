import unittest

import fakes

from hookguard.secrets import SecretScanner, redact, shannon_entropy


def ids(line, **kw):
    return [f.rule for f in SecretScanner(**kw).scan_text("x.py", 1, line)]


# Fixtures are assembled at runtime (tests/fakes.py) so this file doesn't trip secret scanners.
GH, STRIPE, AWS, PW = fakes.GH_TOKEN, fakes.STRIPE_KEY, fakes.AWS_KEY_ID, fakes.STRONG_PASSWORD


class SecretTests(unittest.TestCase):
    def test_provider_keys(self):
        self.assertEqual(ids(f'KEY = "{AWS}"'), ["aws-access-key-id"])
        self.assertEqual(ids(f"token: {GH}"), ["github-token"])
        self.assertEqual(ids(f"stripe.api_key = '{STRIPE}'"), ["stripe-secret-key"])
        self.assertIn("private-key", ids("-----BEGIN RSA PRIVATE KEY-----"))

    def test_generic_assignment_needs_entropy(self):
        self.assertEqual(ids(f'password = "{PW}"'), ["generic-secret-assignment"])
        self.assertEqual(ids('password = "aaaaaaaaaaaa"'), [])  # low entropy

    def test_placeholders_and_env_lookups_are_ignored(self):
        for line in [
            'api_key = "your_api_key_here"',
            'password = "changeme"',
            'secret = "${SECRET_FROM_ENV}"',
            'API_KEY = os.environ["API_KEY"]',
            'token = "<insert-token>"',
            'password = "__DB_PASSWORD__"',  # dunder template placeholder
        ]:
            self.assertEqual(ids(line), [], line)

    def test_suppression_comment(self):
        self.assertEqual(ids(f'password = "{PW}"  # hookguard: ignore'), [])

    def test_allowlist(self):
        self.assertEqual(ids(f'KEY = "{AWS}"', allowlist=["EXAMPLE$"]), [])

    def test_url_credentials(self):
        self.assertEqual(ids(f'DB = "postgres://admin:{fakes.URL_PASSWORD}@db:5432/app"'), ["url-credentials"])

    def test_no_duplicate_generic_match_for_specific_key(self):
        self.assertEqual(ids(f'github_token = "{GH}"'), ["github-token"])

    def test_redaction(self):
        self.assertEqual(redact(AWS), "AKIA" + "*" * 12)
        f = SecretScanner().scan_text("x", 1, f'k = "{AWS}"')[0]
        self.assertNotIn(fakes.AWS_KEY_ID_TAIL, f.snippet)

    def test_entropy(self):
        self.assertLess(shannon_entropy("aaaa"), 0.1)
        self.assertGreater(shannon_entropy("aB3$xY9!"), 2.9)


if __name__ == "__main__":
    unittest.main()
