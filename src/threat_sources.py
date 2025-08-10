"""
sources.py

Top 3 trusted threat intelligence sources.(reduced from 10 to 3 for running the code)

List of threat intelligence data sources to fetch.
Each source is a dict with:
- name: Friendly name / filename to save as
- url: URL or API endpoint
- type: data type (json, text, xml, gzip_json, etc.)
- method: HTTP method (GET or POST)
- requires_api_key: if True, use API key from environment variable (optional)
- api_key_env_var: environment variable name for the API key
"""

sources = [
    {
        "name": "cert_us_alerts.xml",
        "url": "https://us-cert.cisa.gov/ncas/alerts.xml",
        "type": "xml_utf8",
        "method": "GET",
        "requires_api_key": False
    },
    {
        "name": "urlhaus_recent.json",
        "url": "https://urlhaus-api.abuse.ch/v1/urls/recent",
        "type": "json_api",
        "method": "GET",
        "requires_api_key": False
    },
    {
        "name": "cisa_kev.json",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "type": "json",
        "method": "GET",
        "requires_api_key": False
    },
    
]
