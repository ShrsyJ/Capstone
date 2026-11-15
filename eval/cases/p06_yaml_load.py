import yaml

def load_settings(uploaded_file):
    return yaml.load(uploaded_file.read())
