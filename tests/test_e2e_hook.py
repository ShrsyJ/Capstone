"""End-to-end: a real git repo, the installed hook, and a fake Ollama server."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import fakes
from fake_llm import FakeOllama

SRC = str(Path(__file__).resolve().parents[1] / "src")


@unittest.skipUnless(shutil.which("git"), "git not installed")
class HookE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.env = dict(os.environ, PYTHONPATH=SRC, NO_COLOR="1",
                        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")
        self.env.pop("HOOKGUARD_SKIP", None)
        self.git("init", "-q")
        self.git("config", "commit.gpgsign", "false")
        out = subprocess.run([sys.executable, "-m", "hookguard", "install"], cwd=self.repo,
                             env=self.env, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, env=self.env, capture_output=True, text=True)

    def commit_file(self, name, content):
        (self.repo / name).write_text(content)
        self.git("add", name)
        return self.git("commit", "-m", f"add {name}")

    def test_secret_blocks_even_without_a_model(self):
        self.env["HOOKGUARD_HOST"] = "http://127.0.0.1:9"  # unreachable
        r = self.commit_file("cfg.py", f'AWS = "{fakes.AWS_KEY_ID}"\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Commit blocked", r.stdout + r.stderr)
        self.assertNotIn(fakes.AWS_KEY_ID_TAIL, r.stdout + r.stderr)  # secret is masked in output

    def test_clean_commit_passes_and_llm_issue_blocks(self):
        with FakeOllama() as fake:
            self.env.update(HOOKGUARD_HOST=fake.url, HOOKGUARD_MODEL="fake-model")
            r = self.commit_file("ok.py", "def add(a, b):\n    return a + b\n")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(len(fake.requests), 1)

            r = self.commit_file("bad.py", "def h(x):\n    return danger(x)\n")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("danger() called with user input", r.stdout + r.stderr)

    def test_no_verify_bypasses(self):
        (self.repo / "cfg.py").write_text(f'AWS = "{fakes.AWS_KEY_ID}"\n')
        self.git("add", "cfg.py")
        r = self.git("commit", "--no-verify", "-m", "bypass")
        self.assertEqual(r.returncode, 0)

    def test_model_down_warns_but_allows(self):
        self.env["HOOKGUARD_HOST"] = "http://127.0.0.1:9"
        r = self.commit_file("ok.py", "x = 1\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("cannot reach", r.stdout + r.stderr)  # git sends hook stdout to stderr


if __name__ == "__main__":
    unittest.main()
