"""Fake credentials for tests, assembled at runtime from pieces.

No complete secret-shaped string appears in this repository's source, so neither
GitHub push protection nor hookguard itself flags our own commits. All values
are fake (the AWS one is Amazon's documented example key ID).
"""

AWS_KEY_ID = "AKIA" + "IOSFODNN7" + "EXAMPLE"
AWS_KEY_ID_TAIL = AWS_KEY_ID[4:]  # the part that must never appear in output
GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
STRIPE_KEY = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
STRONG_PASSWORD = "Xk9#" + "mP2$" + "vL8qR4!z"
URL_PASSWORD = "Pq7#" + "xZ2!w"
