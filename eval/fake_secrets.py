"""Fake credentials for eval cases, assembled at runtime from pieces.

Case files contain tokens like __HG_FAKE_AWS_KEY_ID__ instead of secret-shaped
strings, so the repository never holds a complete (even fake) credential.
`materialize()` swaps the tokens for the values below when a case is loaded.
Every value here is fake; the AWS pair is Amazon's documented example.
"""

from __future__ import annotations

import re

FAKE_SECRETS = {
    "AWS_KEY_ID": "AKIA" + "IOSFODNN7" + "EXAMPLE",
    "AWS_SECRET": "wJalrXUtnFEMI/" + "K7MDENG/" + "bPxRfiCY" + "EXAMPLEKEY",
    "DB_PASSWORD": "Wq8!" + "zR2#" + "pLm4",
    "SMTP_PASSWORD": "Tr0ub4dor" + "&3xQ!9vZ",
}

_TOKEN_RE = re.compile(r"__HG_FAKE_([A-Z0-9_]+?)__")


def materialize(text: str) -> str:
    """Replace every __HG_FAKE_<NAME>__ token with its fake value."""

    def sub(m: "re.Match[str]") -> str:
        name = m.group(1)
        if name not in FAKE_SECRETS:
            raise KeyError(f"unknown fake secret token {m.group(0)}")
        return FAKE_SECRETS[name]

    return _TOKEN_RE.sub(sub, text)
