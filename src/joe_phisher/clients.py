"""Small HTTP clients written against the public API contracts."""

import logging
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote, urlsplit

import requests

from . import __version__
from .config import MANAGED_TAGS, https_url

# Agreement Exhibit A, section 4: identify the integration and its release version.
USER_AGENT = f"JoeSandbox-PhishER/{__version__}"

# Fixed limits keep the public configuration small and bound per-cycle work and memory.
DISCOVERY_PAGE_SIZE = 100
MAX_DISCOVERY_PAGES = 10
MAX_EML_BYTES = 50 * 1024 * 1024

class ApiError(Exception):
    """Contains only safe, locally generated diagnostics; never response bodies."""


class Retryable(ApiError):
    def __init__(self, message: str, retry_after: int = 60):
        super().__init__(message)
        self.retry_after = max(1, retry_after)


class AmbiguousSubmission(ApiError):
    pass


class FatalAuth(ApiError):
    pass


class ReverserNotLicensed(ApiError):
    """A definite rejection before submission acceptance, safe for one fallback."""


def retry_delay(value: str) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        try:
            return max(1, int((parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()))
        except (TypeError, ValueError, OverflowError):
            return 60


class Transport:
    def __init__(self, timeout=30, session=None, proxy_url=""):
        self.timeout = timeout
        self.session = session or requests.Session()
        # Only the explicit TOML setting controls routing; ignore inherited proxies/netrc.
        self.session.trust_env = False
        self.session.proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else {}
        self.session.verify = True
        self.session.headers.update({"User-Agent": USER_AGENT})
        # requests' default adapter does not automatically retry POSTs.

    def download(self, url):
        """Retrieve opaque EML bytes in bounded memory; never open or execute content."""
        response = None
        try:
            # rawUrl is a signed download URL, not an authenticated GraphQL request.
            response = self.session.get(url, timeout=(10, self.timeout), allow_redirects=False,
                                        stream=True, headers={"Authorization": None})
            status = response.status_code
            if status == 407:
                raise FatalAuth("Proxy authentication failed (HTTP 407)")
            if status == 429:
                raise Retryable("Email download rate limit", retry_delay(response.headers.get("Retry-After")))
            if status in {401, 403, 404, 408, 425} or status >= 500:
                raise Retryable(f"Email download unavailable (HTTP {status}); refresh PhishER URL")
            if not 200 <= status < 300:
                raise ApiError(f"Email download failed (HTTP {status}); redirects are not followed")
            length = response.headers.get("Content-Length", "")
            if length.isdigit() and int(length) > MAX_EML_BYTES:
                raise ApiError("Email exceeds the 50 MiB download limit")
            data = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                if len(data) + len(chunk) > MAX_EML_BYTES:
                    raise ApiError("Email exceeds the 50 MiB download limit")
                data.extend(chunk)
            if not data:
                raise ApiError("PhishER returned an empty email download")
            return bytes(data)
        except requests.RequestException:
            raise Retryable("Email download transport failed; refresh PhishER URL") from None
        finally:
            if response is not None:
                response.close()

    def post(self, url, *, submission=False, **kwargs):
        # Submission failures need special handling: a missing response can still mean accepted.
        try:
            response = self.session.post(url, timeout=(10, self.timeout), allow_redirects=False, **kwargs)
        except requests.RequestException:
            if submission:
                raise AmbiguousSubmission("Submission response lost; reconcile before retrying") from None
            raise Retryable("API transport failed") from None
        try:
            status = response.status_code
            if (status == 400 and submission
                    and kwargs.get("data", {}).get("analyze-on-reverser") == "1"):
                # The API uses this specific rejection when the account lacks Reverser.
                # Never infer it from an arbitrary error or an uncertain upload response.
                try:
                    rejected = response.json()
                except ValueError:
                    rejected = {}
                if isinstance(rejected, dict) and not rejected.get("data"):
                    errors = rejected.get("errors")
                    if (isinstance(errors, list) and len(errors) == 1 and isinstance(errors[0], dict)
                            and errors[0].get("code") == 1
                            and errors[0].get("message") == "Joe Reverser is not enabled for your account"):
                        raise ReverserNotLicensed("Joe Reverser is not licensed for this account")
            if status == 407:
                raise FatalAuth("Proxy authentication failed (HTTP 407)")
            if status in {401, 403}:
                raise FatalAuth(f"API authentication/authorization failed (HTTP {status})")
            if status == 429:
                raise Retryable("API rate limit", retry_delay(response.headers.get("Retry-After")))
            if status >= 500 or status in {408, 425}:
                if submission:
                    raise AmbiguousSubmission(f"Submission outcome uncertain (HTTP {status})")
                raise Retryable(f"API temporarily unavailable (HTTP {status})")
            if not 200 <= status < 300:
                raise ApiError(f"API rejected request (HTTP {status}); redirects are not followed")
            try:
                data = response.json()
            except ValueError:
                if submission:
                    raise AmbiguousSubmission("Submission returned invalid JSON") from None
                raise Retryable("API returned invalid JSON") from None
            if not isinstance(data, dict):
                if submission:
                    raise AmbiguousSubmission("Submission returned an unexpected envelope")
                raise ApiError("API returned an unexpected envelope")
            return data
        finally:
            response.close()


def lucene_quote(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


MESSAGE_FIELDS = "id rawUrl actionStatus pipelineStatus tags { name } comments { body }"


class Phisher:
    def __init__(self, config, token, transport=None):
        self.config = config
        self.transport = transport or Transport(config.request_timeout, proxy_url=config.proxy_url)
        self.headers = {"Authorization": f"Bearer {token}"}
        self.discovery_page = 1
        self.discovery_cursor = None

    def graphql(self, operation, variables, field):
        payload = self.transport.post(
            self.config.phisher_endpoint, params={"scope": "phisher"}, headers=self.headers,
            json={"query": operation, "variables": variables})
        # GraphQL may return HTTP 200 with top-level errors or mutation-specific errors.
        if payload.get("errors"):
            raise ApiError("PhishER GraphQL errors; check endpoint, token scope and schema")
        data = payload.get("data")
        if not isinstance(data, dict) or field not in data or data[field] is None:
            raise ApiError(f"PhishER returned no {field} result")
        result = data[field]
        if isinstance(result, dict) and result.get("errors"):
            raise ApiError(f"PhishER {field} returned mutation errors")
        return result

    def discovery_query(self):
        # Combine the optional request tag and search with exclusions for all connector tags.
        clauses = [f"-tags:{lucene_quote(tag)}" for tag in MANAGED_TAGS]
        if self.config.ingestion_tag:
            clauses.append(f"tags:{lucene_quote(self.config.ingestion_tag)}")
        if self.config.message_filter:
            clauses.append(f"({self.config.message_filter})")
        return " AND ".join(clauses)

    def discover(self):
        operation = """query Discover($query:String!, $page:Int!, $per:Int!, $cursor:String) {
          phisherMessages(query:$query,page:$page,per:$per,nextPageKey:$cursor) {
            nodes { id actionStatus pipelineStatus tags { name } }
            pagination { page pages nextPageKey }
          }
        }"""
        # Retain pagination progress between scans instead of always revisiting page one.
        for _ in range(MAX_DISCOVERY_PAGES):
            page, cursor = self.discovery_page, self.discovery_cursor
            result = self.graphql(operation, {"query": self.discovery_query(), "page": page,
                                              "per": DISCOVERY_PAGE_SIZE, "cursor": cursor}, "phisherMessages")
            nodes = result.get("nodes") or []
            for node in nodes:
                if self.eligible(node):
                    yield node["id"]
            pagination = result.get("pagination") or {}
            self.discovery_cursor = pagination.get("nextPageKey")
            self.discovery_page = page + 1
            # PhishER returns a null page count when a search has no matches.
            pages = pagination.get("pages")
            if not nodes or (not self.discovery_cursor and (pages is None or page >= pages)):
                self.discovery_page, self.discovery_cursor = 1, None
                break

    def eligible(self, message):
        # Recheck API fields locally as well as using the server-side search expression.
        tags = {tag["name"].casefold() for tag in message.get("tags") or []}
        return (message.get("pipelineStatus") == "PROCESSED"
                and message.get("actionStatus") != "RESOLVED"
                and not any(tag.casefold() in tags for tag in MANAGED_TAGS)
                and (not self.config.ingestion_tag or self.config.ingestion_tag.casefold() in tags))

    def message(self, message_id):
        return self.graphql(f"query Message($id:String!) {{ phisherMessage(id:$id) {{ {MESSAGE_FIELDS} }} }}",
                            {"id": message_id}, "phisherMessage")

    def download_email(self, raw_url):
        # Signed HTTPS query parameters are expected; embedded login credentials are not.
        try:
            parsed = urlsplit(raw_url)
            valid = (parsed.scheme == "https" and parsed.hostname and not parsed.username
                     and not parsed.password and not parsed.fragment)
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise ApiError("PhishER rawUrl must be HTTPS without embedded credentials or a fragment")
        return self.transport.download(raw_url)

    def tags(self, message_id, tags, delete=False):
        if not tags:
            return
        name = "phisherTagsDelete" if delete else "phisherTagsCreate"
        self.graphql(f"mutation Tags($id:String!,$tags:[String!]!) {{ {name}(id:$id,tags:$tags) {{ errors {{ reason }} nodes {{ name }} }} }}",
                     {"id": message_id, "tags": tags}, name)

    def ensure_comment(self, message_id, body, marker):
        # Recover an acknowledged-by-server but lost response before creating a second comment.
        existing = self.message(message_id).get("comments") or []
        # Recognize references written before the branding change when resuming old jobs.
        references = (marker, marker.replace("[KnowBe4-PhishER:", "[joe-phisher:"))
        # Compact comments have no visible tracking footer; reconcile their text instead.
        same_text = any(" ".join((comment.get("body") or "").split()) == " ".join(body.split())
                        for comment in existing)
        if same_text or any(reference in (comment.get("body") or "")
                            for comment in existing for reference in references):
            return
        self.graphql("""mutation Comment($id:String!,$comment:String!) {
          phisherCommentCreate(id:$id,comment:$comment) { errors { reason } node { body } }
        }""", {"id": message_id, "comment": body}, "phisherCommentCreate")

    def mark_threat(self, message_id):
        self.graphql("""mutation Threat($id:String!) {
          phisherMessageUpdate(id:$id,payload:{category:THREAT}) { errors { reason } node { id } }
        }""", {"id": message_id}, "phisherMessageUpdate")


class JoeSandbox:
    def __init__(self, config, api_key, transport=None):
        self.config, self.api_key = config, api_key
        self.transport = transport or Transport(config.request_timeout, proxy_url=config.proxy_url)
        self.reverser_available = config.enable_reverser
        self.last_submission_reverser = False
        self.last_submission_reverser_fallback = False

    def call(self, endpoint, values=None, submission=False, files=None):
        # requests switches to multipart encoding when the submission includes a sample file.
        data = {"apikey": self.api_key, **(values or {})}
        payload = self.transport.post(self.config.joe_api_url.rstrip("/") + "/v2/" + endpoint,
                                      data=data, submission=submission, files=files)
        if payload.get("error") or payload.get("errors"):
            raise ApiError(f"Joe Sandbox rejected {endpoint}; check account limits and options")
        result = payload.get("data")
        if not isinstance(result, (dict, list)):
            if submission:
                raise AmbiguousSubmission("Joe Sandbox returned no submission data")
            raise ApiError("Joe Sandbox returned no data")
        return result

    def submit(self, eml, marker):
        if not isinstance(eml, bytes) or not eml:
            raise ApiError("Joe Sandbox submission requires non-empty EML bytes")
        requested = self.config.enable_reverser and self.reverser_available
        params = {"accept-tac": "1", "comments": marker,
                  "analyze-on-reverser": "1" if requested else "0",
                  "report-cache": "1" if self.config.enable_cache else "0"}
        # Preserve the original bytes, including MIME boundaries and attachment encodings.
        files = {"sample": ("message.eml", eml, "message/rfc822")}
        try:
            result = self.call("submission/new", params, submission=True, files=files)
        except ReverserNotLicensed:
            if not requested:
                raise
            self.reverser_available = False
            requested = False
            params = {**params, "analyze-on-reverser": "0"}
            logging.getLogger(__name__).warning("Joe Reverser is not licensed; retrying with Joe Sandbox only")
            result = self.call("submission/new", params, submission=True, files=files)
        if not isinstance(result, dict) or not result.get("submission_id"):
            raise AmbiguousSubmission("Joe Sandbox returned no submission ID")
        self.last_submission_reverser = requested
        self.last_submission_reverser_fallback = self.config.enable_reverser and not requested
        return str(result["submission_id"])

    def submission(self, submission_id):
        # Include already-created Reverser analyses even if the option is later disabled.
        return self.call("submission/info", {"submission_id": submission_id, "include-reverser-analyses": "1"})

    def analysis(self, webid):
        result = self.call("analysis/info", {"webid": webid})
        if not isinstance(result, dict) or str(result.get("webid")) != str(webid):
            raise ApiError("Joe Sandbox analysis ID does not match the requested ID")
        return result

    def report_link(self, webid, analysis_type=None):
        if analysis_type == "reverser" or str(webid).startswith("r-"):
            public_id = str(webid)[2:] if str(webid).startswith("r-") else str(webid)
            return https_url(self.config.joe_report_url) + "/joereverser/analysis/" + quote(public_id, safe="")
        return https_url(self.config.joe_report_url) + "/analysis/" + quote(str(webid), safe="") + "/0/html"


def normalize_verdict(value):
    if isinstance(value, str) and value.lower() in {"malicious", "suspicious", "clean"}:
        return value.lower()
    return "unknown"


def aggregate_verdict(values):
    values = list(values)
    if "malicious" in values:
        return "malicious"
    if "suspicious" in values:
        return "suspicious"
    return "clean" if values and all(value == "clean" for value in values) else "unknown"


def analysis_summary(info, link, analysis_type=None):
    """Use the reported verdict, including every run; never derive it from a score."""
    runs = info.get("runs") or []
    verdicts = [normalize_verdict(info.get("detection"))]
    verdicts.extend(normalize_verdict(run.get("detection")) for run in runs)
    # An absent summary verdict is normal when only run verdicts are returned.
    if "detection" not in info and runs:
        verdicts = verdicts[1:]
    verdict = aggregate_verdict(verdicts)
    errors = sum(bool(run.get("error")) for run in runs) + bool(info.get("error"))
    if errors and verdict == "clean":
        # An unsuccessful run cannot establish that a message is clean.
        verdict = "unknown"
    scores = [info.get("score")] + [run.get("score") for run in runs]
    scores = [score for score in scores if type(score) in {int, float} and 0 <= score <= 100]
    digest = info.get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        digest = None
    threatname = info.get("threatname")
    threatname = " ".join(threatname.split()) if isinstance(threatname, str) else ""
    return {"webid": str(info["webid"]), "verdict": verdict,
            "score": max(scores) if scores else None, "sha256": digest, "link": link,
            "run_errors": errors, "threatname": threatname,
            "analysis_type": analysis_type or info.get("analysis_type") or
            ("reverser" if str(info["webid"]).startswith("r-") else "sandbox")}
