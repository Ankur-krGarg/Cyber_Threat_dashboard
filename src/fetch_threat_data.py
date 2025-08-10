"""
fetch_data.py

Fetch threat intelligence data from multiple sources and save locally.
Creates ../data folder if not exists.

Supports:
- GET and POST methods
- gzip decompression
- API keys from environment variables (for AlienVault OTX)
"""

import os
import requests
import gzip
import io
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
from threat_sources import sources

DATA_DIR = "./data"
#os.makedirs(DATA_DIR, exist_ok=True)

output_dir = Path(DATA_DIR)
output_dir.mkdir(exist_ok=True)

def fetch_source(source):
    name = source['name']
    url = source['url']
    typ = source.get('type', 'json')
    method = source.get('method', 'GET').upper()
    requires_api_key = source.get('requires_api_key', False)
    api_key_env_var = source.get('api_key_env_var', None)
    post_payload = source.get('post_payload', None)

    print(f"Fetching {name} from {url} ...")

    headers = {}
    if requires_api_key and api_key_env_var:
        api_key = os.getenv(api_key_env_var)
        if not api_key:
            print(f"ERROR: API key for {name} not found in environment variable '{api_key_env_var}'. Skipping.")
            return
        # Set headers according to API docs (example for AlienVault)
        headers = {"X-OTX-API-KEY": api_key}

    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=20)
        elif method == "POST":
            response = requests.post(url, json=post_payload, headers=headers, timeout=20)
        else:
            print(f"Unsupported HTTP method {method} for {name}")
            return

        response.raise_for_status()

        filepath = os.path.join(DATA_DIR, name)

        if typ == 'gzip_json':
            with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as f:
                data = f.read()
            with open(filepath, "wb") as f:
                f.write(data)
            print(f"Saved decompressed gzip data to {filepath}")

        elif typ == 'xml_utf8':
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(response.text)
            print(f"Saved XML (utf-8) data to {filepath}")

        elif typ == 'json_api' or typ == 'json':
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(response.text)
            print(f"Saved JSON data to {filepath}")

        elif typ == 'text':
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(response.text)
            print(f"Saved text data to {filepath}")

        else:
            print(f"Unknown type '{typ}' for {name}, saving raw content.")
            with open(filepath, "wb") as f:
                f.write(response.content)

    except Exception as e:
        print(f"Failed to fetch {name}: {e}")

def main():
    for source in sources:
        fetch_source(source)

if __name__ == "__main__":
    main()
