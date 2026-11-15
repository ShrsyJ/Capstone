import json
import yaml

def load(path):
    with open(path) as fh:
        if path.endswith(".json"):
            return json.load(fh)
        return yaml.safe_load(fh)
