"""
sources.py

(File with 10 sources)

Top 10 trusted threat intelligence sources.

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
        "name": "nvd_recent_cves.json",
        "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
        "type": "gzip_json",
        "method": "GET",
        "requires_api_key": False
    },
    {
        "name": "cert_us_alerts.xml",
        "url": "https://us-cert.cisa.gov/ncas/alerts.xml",
        "type": "xml_utf8",
        "method": "GET",
        "requires_api_key": False
    },
    {
        "name": "openphish_urls.txt",
        "url": "https://openphish.com/feed.txt",
        "type": "text",
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
    {
        "name": "alienvault_otx.json",
        "url": "https://otx.alienvault.com/api/v1/indicators/export",
        "type": "json_api",
        "method": "GET",
        "requires_api_key": True,
        "api_key_env_var": "ALIENVAULT_API_KEY"
    },
    {
        "name": "malwarebazaar_recent.json",
        "url": "https://mb-api.abuse.ch/api/v1/",
        "type": "json_api",
        "method": "POST",
        "post_payload": {"query": "get_recent"},
        "requires_api_key": False
    },
    {
        "name": "phishtank_urls.json",
        "url": "https://data.phishtank.com/data/online-valid.json",
        "type": "json",
        "method": "GET",
        "requires_api_key": False
    },
    {
        "name": "threatfox_iocs.json",
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "type": "json_api",
        "method": "POST",
        "post_payload": {"query": "get_iocs"},
        "requires_api_key": False
    },
    {
        "name": "Blocklist DE",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "type": "text",
        "filename": "blocklist_de.txt"
    },
]

