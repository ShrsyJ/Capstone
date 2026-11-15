import os

API_KEY = os.environ.get("PAYMENTS_API_KEY")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///local.db")
# Example: export PAYMENTS_API_KEY="your-api-key-here"
