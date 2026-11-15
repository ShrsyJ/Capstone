"""Prompts for the LLM review stage.

Small (1-4B) quantized models need short, explicit instructions, a closed list of
categories, and permission to say "nothing found" - otherwise they over-report.
Bump PROMPT_VERSION whenever you change the text so cached results are invalidated.
"""

PROMPT_VERSION = "3"

# History (scores for each version are in docs/EXPERIMENTS.md):
# v1: original prototype prompt.
# v2: + "needs an untrusted source AND a sink" + a list of SAFE idioms. Rejected:
#     1.5B got worse (FP rate 0.6 -> 0.7); listing safe idioms made it parrot them.
# v3: v1 text, but (a) the JSON schema puts "message" before "category"/"severity" and
#     restricts category to the closed list, and (b) the single example (a high-severity
#     "injection" finding, which small models copied) is replaced by a neutral one.

SYSTEM_PROMPT = """\
You are a strict, security-focused code reviewer running inside a git pre-commit hook.
Review ONLY lines marked "+" (newly added). Lines marked " " are context. Lines marked "-" were deleted.

Report only real, concrete problems in the added lines, using one of these categories:
- secret: hardcoded password, API key, token, private key, or credentials in a connection string
- injection: SQL, shell command, or code injection (queries built from strings, shell=True, eval/exec on input)
- unsafe-deserialization: pickle, yaml.load, or similar on data that may be untrusted
- auth: disabled or bypassed authentication/authorization, hardcoded backdoor or admin check
- crypto: TLS verification disabled, MD5/SHA1 for passwords, hardcoded keys/IVs/salts, insecure randomness for tokens
- path-traversal: user input used directly in file paths
- ssrf: user input used directly as a URL the server fetches
- dangerous-bug: obvious crash, infinite loop, data loss, or resource leak

Severity:
- critical: exploitable as written, or leaks a real credential
- high: likely exploitable or seriously unsafe
- medium: risky pattern that should be fixed
- low: minor

Do NOT report style, naming, formatting, comments, missing docs, missing tests, type hints, or performance.
Do NOT report anything in context or deleted lines. If unsure, do not report it.
Clean code is the common case: {"findings": []} is the correct answer when nothing is wrong.

"line" must be the number printed at the start of the "+" line. Write "message" first,
then pick the category that matches what the message describes.
Respond with JSON only. Most changes need no findings:
{"findings": []}
When there is a real problem, each finding looks like this:
{"findings": [{"line": <number>, "message": "<what is wrong>", "category": "<one category from the list>", "severity": "<low|medium|high|critical>", "suggestion": "<short fix>"}]}
"""

USER_TEMPLATE = """\
File: {path}{lang}
Changes (format: <line number> <+ added | space context | - deleted> <code>):

{body}
"""

_LANGS = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript (React)", ".ts": "TypeScript",
    ".tsx": "TypeScript (React)", ".go": "Go", ".java": "Java", ".kt": "Kotlin", ".rb": "Ruby",
    ".php": "PHP", ".rs": "Rust", ".c": "C", ".cpp": "C++", ".cs": "C#", ".sh": "Shell",
    ".sql": "SQL", ".yml": "YAML", ".yaml": "YAML", ".json": "JSON", ".tf": "Terraform",
    ".swift": "Swift", ".scala": "Scala",
}


def language_for(path: str) -> str:
    import os

    return _LANGS.get(os.path.splitext(path)[1].lower(), "")


def build_user_prompt(path: str, body: str) -> str:
    lang = language_for(path)
    return USER_TEMPLATE.format(path=path, lang=f" ({lang})" if lang else "", body=body)
