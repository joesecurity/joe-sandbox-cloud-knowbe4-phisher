"""TOML configuration, including API credentials as strings."""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


def https_url(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment or parsed.query):
        raise ValueError("API/report base URLs must be HTTPS without credentials, query or fragment")
    return value.rstrip("/")


# These exact labels are written to PhishER and also exclude already handled messages.
SUBMITTED = "Joe Sandbox Submitted"
MALICIOUS = "Joe Sandbox Malicious"
SUSPICIOUS = "Joe Sandbox Suspicious"
ERROR = "Joe Sandbox Error"
TIMEOUT = "Joe Sandbox Timeout"
REVIEW = "Joe Sandbox Review Required"
MANAGED_TAGS = (SUBMITTED, MALICIOUS, SUSPICIOUS, ERROR, TIMEOUT, REVIEW)

@dataclass(frozen=True)
class Config:
    # Hide credentials, including an authenticated proxy URL, from the generated repr.
    phisher_endpoint: str = "https://training.knowbe4.com/graphql"
    phisher_api_token: str = field(default="", repr=False)
    ingestion_tag: str = ""
    message_filter: str = ""
    set_category_on_malicious: bool = True
    joe_api_url: str = "https://jbxcloud.joesecurity.org/api"
    joe_report_url: str = "https://jbxcloud.joesecurity.org"
    joe_api_key: str = field(default="", repr=False)
    enable_reverser: bool = True
    enable_cache: bool = False
    proxy_url: str = field(default="", repr=False)
    # Cloud terms acceptance is fixed in code; it is not a TOML option.
    accept_tac: bool = True
    discovery_interval: int = 60
    request_timeout: int = 30
    job_timeout: int = 7200
    state_path: str = "/data/state.sqlite3"

    @classmethod
    def read(cls, filename: str):
        if Path(filename).suffix != ".toml":
            raise ValueError("Configuration must be a .toml file")
        with open(filename, "rb") as handle:
            raw = tomllib.load(handle)
        # Translate the user-facing TOML names to the attributes used by the API clients.
        fields = {
            "knowbe4": {
                "graphql_url": "phisher_endpoint",
                "product_api_token": "phisher_api_token",
                "required_tag": "ingestion_tag",
                "email_search": "message_filter",
                "mark_threat_on_malicious": "set_category_on_malicious",
            },
            "joe_sandbox": {
                "cloud_api_url": "joe_api_url",
                "report_base_url": "joe_report_url",
                "cloud_api_key": "joe_api_key",
                "enable_reverser": "enable_reverser",
                "enable_cache": "enable_cache",
            },
            "connection": {"proxy_url": "proxy_url", "timeout_seconds": "request_timeout"},
            "service": {
                "check_mail_every_seconds": "discovery_interval",
                "max_wait_seconds": "job_timeout",
                "database_path": "state_path",
            },
        }
        for section, values in raw.items():
            # Reject typos instead of silently using a default for an unrecognized option.
            if section not in fields or not isinstance(values, dict):
                raise ValueError(f"Unknown configuration section: {section}")
            if set(values) - fields[section].keys():
                raise ValueError(f"Unknown configuration option in section: {section}")
        kwargs = {}
        for section, values in raw.items():
            for key, value in values.items():
                kwargs[fields[section][key]] = value
        config = cls(**kwargs)
        public_names = {attribute: f"{section}.{key}" for section, values in fields.items()
                        for key, attribute in values.items()}
        # Validation errors identify the setting without echoing its credential value.
        for key in ("phisher_endpoint", "joe_api_url", "joe_report_url"):
            https_url(getattr(config, key))
        for key in ("ingestion_tag", "message_filter", "state_path", "phisher_api_token", "joe_api_key", "proxy_url"):
            if not isinstance(getattr(config, key), str):
                raise ValueError(f"{public_names[key]} must be a string")
        if config.proxy_url:
            try:
                proxy = urlsplit(config.proxy_url)
                valid = (proxy.scheme in {"http", "https"} and proxy.hostname
                         and (proxy.port is None or 1 <= proxy.port <= 65535)
                         and proxy.path in {"", "/"} and not proxy.query and not proxy.fragment
                         and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in config.proxy_url))
            except ValueError:
                valid = False
            if not valid:
                raise ValueError("connection.proxy_url must be an HTTP(S) proxy URL without a path, query or fragment")
        for key in ("phisher_api_token", "joe_api_key"):
            value = getattr(config, key)
            if value != value.strip() or any(c in value for c in "\r\n"):
                raise ValueError(f"{public_names[key]} must not contain surrounding whitespace or line breaks")
        for key in ("set_category_on_malicious", "enable_reverser", "enable_cache"):
            if type(getattr(config, key)) is not bool:
                raise ValueError(f"{public_names[key]} must be a boolean")
        for key in ("discovery_interval", "request_timeout", "job_timeout"):
            # Use exact types because bool is an int subclass in Python.
            if type(getattr(config, key)) is not int or getattr(config, key) <= 0:
                raise ValueError(f"{public_names[key]} must be a positive integer")
        if config.ingestion_tag.casefold() in {tag.casefold() for tag in MANAGED_TAGS}:
            # A result tag cannot also be the request tag without conflicting discovery rules.
            raise ValueError("knowbe4.required_tag must not be a result/status tag")
        return config
