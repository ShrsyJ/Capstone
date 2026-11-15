import subprocess

def current_branch():
    out = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, check=True)
    return out.stdout.strip()
