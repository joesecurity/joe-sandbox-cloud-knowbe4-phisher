"""Offline contract and recovery tests. No network or real samples are used."""

import json
import tomllib
import io
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from joe_phisher import __version__
from joe_phisher.clients import (AmbiguousSubmission, ApiError, FatalAuth, JoeSandbox,
                                 Phisher, Retryable, Transport, aggregate_verdict,
                                 analysis_summary, retry_delay)
from joe_phisher.comments import final_comment
from joe_phisher.config import (ERROR, MALICIOUS, REVIEW, SUBMITTED,
                                SUSPICIOUS, TIMEOUT, Config)
from joe_phisher.__main__ import main
from joe_phisher.state import State, instance_lock
from joe_phisher.worker import Worker


class FakeServices:
    """Exercise real clients and worker against deterministic API-shaped responses."""

    # This fake records remote writes in memory; no test needs a live service or API key.

    def __init__(self):
        self.calls = []
        self.downloaded_urls = []
        self.email_bytes = b"From: sender@example.test\r\nTo: recipient@example.test\r\nSubject: test\r\n\r\nTest body.\r\n"
        self.download_error = None
        self.messages = {"m1": {"id": "m1", "rawUrl": "https://download.example/email.eml?sig=private",
                                "pipelineStatus": "PROCESSED", "actionStatus": "RECEIVED",
                                "tags": [{"name": "Customer tag"}], "comments": []}}
        self.submit_count = 0
        self.submission_status = "running"
        self.analysis_status = "finished"
        self.detection = "malicious"
        self.reverser_detection = "suspicious"
        self.reverser_status = "finished"
        self.submit_error = None
        self.comment_response_lost = False
        self.publish_error = False
        self.extra_analyses = []

    def download(self, url):
        self.downloaded_urls.append(url)
        if self.download_error:
            raise self.download_error
        return self.email_bytes

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if "json" in kwargs:
            operation = kwargs["json"]["query"]
            variables = kwargs["json"]["variables"]
            if "query Discover" in operation:
                return {"data": {"phisherMessages": {"nodes": list(self.messages.values()),
                                                      "pagination": {"pages": 1}}}}
            message = self.messages[variables["id"]]
            if "query Message" in operation:
                return {"data": {"phisherMessage": message}}
            if "phisherTagsCreate" in operation:
                if self.publish_error:
                    raise ApiError("simulated tag failure")
                tags = {tag["name"] for tag in message["tags"]} | set(variables["tags"])
                message["tags"] = [{"name": tag} for tag in sorted(tags)]
                return {"data": {"phisherTagsCreate": {"errors": None, "nodes": message["tags"]}}}
            if "phisherTagsDelete" in operation:
                message["tags"] = [tag for tag in message["tags"] if tag["name"] not in variables["tags"]]
                return {"data": {"phisherTagsDelete": {"errors": [], "nodes": message["tags"]}}}
            if "phisherCommentCreate" in operation:
                message["comments"].append({"body": variables["comment"]})
                if self.comment_response_lost:
                    self.comment_response_lost = False
                    raise Retryable("lost comment response", 1)
                return {"data": {"phisherCommentCreate": {"errors": [], "node": {"body": variables["comment"]}}}}
            if "phisherMessageUpdate" in operation:
                message["category"] = "THREAT"
                return {"data": {"phisherMessageUpdate": {"errors": None, "node": {"id": message["id"]}}}}
            raise AssertionError(operation)
        values = kwargs["data"]
        if url.endswith("/submission/new"):
            self.submit_count += 1
            if self.submit_error:
                raise self.submit_error
            return {"data": {"submission_id": "s1"}}
        if url.endswith("/submission/info"):
            return {"data": {"status": self.submission_status,
                             "analyses": [{"webid": "101", "analysis_type": "sandbox"}] + self.extra_analyses}}
        if url.endswith("/analysis/info"):
            if (str(values["webid"]).startswith("r-") or any(
                    a.get("analysis_type") == "reverser" and a.get("webid") == values["webid"]
                    for a in self.extra_analyses)):
                return {"data": {"webid": values["webid"], "status": self.reverser_status,
                                 "detection": self.reverser_detection, "score": 75, "error": None}}
            return {"data": {"webid": values["webid"], "status": self.analysis_status,
                             "detection": "suspicious" if values["webid"] == "102" else self.detection,
                             "score": 95, "sha256": "a" * 64,
                             "threatname": "Emotet",
                             "runs": [{"detection": self.detection}]}}
        raise AssertionError(url)


class WorkflowTests(unittest.TestCase):
    # Drive the real worker with a controllable clock to test retries without real sleeps.
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = replace(Config(), accept_tac=True, state_path=self.temp.name + "/state.sqlite3")
        self.state = State(self.config.state_path)
        self.addCleanup(self.state.close)
        self.api = FakeServices()
        self.phisher = Phisher(self.config, "test-token", self.api)
        self.joe = JoeSandbox(self.config, "test-key", self.api)
        self.now = 1000000.0
        self.worker = Worker(self.config, self.state, self.phisher, self.joe, clock=lambda: self.now)

    def tick(self, seconds=31):
        self.now += seconds
        self.worker.tick()

    def tags(self):
        return {tag["name"] for tag in self.api.messages["m1"]["tags"]}

    def finish(self):
        self.tick()
        self.api.submission_status = "finished"
        self.tick()

    def test_malicious_round_trip(self):
        self.finish()
        self.assertEqual(self.api.submit_count, 1)
        self.assertTrue({SUBMITTED, MALICIOUS, "Customer tag"} <= self.tags())
        self.assertNotIn("Joe Sandbox Completed", self.tags())
        self.assertNotIn(SUSPICIOUS, self.tags())
        self.assertEqual(self.api.messages["m1"]["category"], "THREAT")
        self.assertEqual(self.state.get("m1")["phase"], "done")
        comment = self.api.messages["m1"]["comments"][-1]["body"]
        self.assertIn("Score: 95/100", comment)
        self.assertIn("Threat name: Emotet", comment)
        self.assertEqual(self.state.get("m1")["results"][0]["threatname"], "Emotet")
        self.assertIn("Report: https://jbxcloud.joesecurity.org/submission/s1", comment)
        self.assertNotIn("/0/html", comment)
        self.assertNotIn("sig=private", json.dumps(self.state.jobs()))
        self.tick(600)
        self.assertEqual(self.api.submit_count, 1)

    def test_suspicious_does_not_change_category(self):
        self.api.detection = "suspicious"
        self.finish()
        self.assertIn(SUSPICIOUS, self.tags())
        self.assertNotIn(MALICIOUS, self.tags())
        self.assertNotIn("category", self.api.messages["m1"])

    def test_category_change_can_be_disabled(self):
        self.worker.config = replace(self.config, set_category_on_malicious=False)
        self.finish()
        self.assertIn(MALICIOUS, self.tags())
        self.assertNotIn("category", self.api.messages["m1"])

    def test_clean_does_not_create_a_malicious_or_suspicious_tag(self):
        self.api.detection = "clean"
        self.finish()
        self.assertNotIn("Joe Sandbox Completed", self.tags())
        self.assertFalse({MALICIOUS, SUSPICIOUS} & self.tags())

    def test_unknown_is_never_clean(self):
        self.api.detection = None
        self.finish()
        self.assertEqual(self.state.get("m1")["verdict"], "unknown")

    def test_requested_tag_removed_only_after_acceptance(self):
        config = replace(self.config, ingestion_tag="Joe Sandbox Request")
        self.phisher.config = self.worker.config = config
        self.tick()
        self.assertEqual(self.api.submit_count, 0)
        self.api.messages["m1"]["tags"].append({"name": config.ingestion_tag})
        self.tick(61)
        self.assertEqual(self.api.submit_count, 1)
        self.assertNotIn(config.ingestion_tag, self.tags())

    def test_api_submission_uploads_original_eml_bytes(self):
        self.tick()
        request = next(kwargs for url, kwargs in self.api.calls if url.endswith("submission/new"))
        self.assertEqual(set(request["data"]), {"apikey", "accept-tac", "comments", "analyze-on-reverser", "report-cache"})
        self.assertEqual(request["files"], {"sample": ("message.eml", self.api.email_bytes, "message/rfc822")})
        self.assertEqual(self.api.downloaded_urls, [self.api.messages["m1"]["rawUrl"]])
        self.assertEqual(request["data"]["accept-tac"], "1")
        self.assertTrue(request["submission"])

    def test_download_retry_does_not_create_a_submission(self):
        self.api.download_error = Retryable("download interrupted", 60)
        self.tick()
        self.assertEqual(self.api.submit_count, 0)
        self.assertEqual(self.state.get("m1")["phase"], "queued")
        self.assertNotIn(SUBMITTED, self.tags())
        self.api.download_error = None
        self.tick(61)
        self.assertEqual(self.api.submit_count, 1)

    def test_eml_is_not_written_to_job_state(self):
        self.finish()
        saved = json.dumps(self.state.jobs())
        self.assertNotIn("Test body.", saved)
        self.assertNotIn("sender@example.test", saved)
        self.assertNotIn("sig=private", saved)

    def test_restart_resumes_without_second_submission(self):
        self.tick()
        reopened = State(self.config.state_path)
        self.addCleanup(reopened.close)
        self.worker = Worker(self.config, reopened, self.phisher, self.joe, clock=lambda: self.now)
        self.api.submission_status = "finished"
        self.tick()
        self.assertEqual(self.api.submit_count, 1)
        self.assertEqual(reopened.get("m1")["phase"], "done")

    def test_lost_submission_response_blocks_retries(self):
        self.api.submit_error = AmbiguousSubmission("Submission response lost")
        self.tick()
        self.tick()
        self.tick(600)
        self.assertEqual(self.api.submit_count, 1)
        self.assertEqual(self.state.get("m1")["phase"], "blocked")
        self.assertIn(REVIEW, self.tags())
        self.assertNotIn(SUBMITTED, self.tags())

    def test_crash_during_submission_requires_review(self):
        self.state.enqueue("m1", self.now)
        job = self.state.get("m1")
        job["phase"] = "submitting"
        self.state.save(job)
        self.worker = Worker(self.config, self.state, self.phisher, self.joe, clock=lambda: self.now)
        self.tick()
        self.assertEqual(self.api.submit_count, 0)
        self.assertEqual(self.state.get("m1")["phase"], "blocked")

    def test_lost_comment_response_is_reconciled(self):
        self.api.comment_response_lost = True
        self.tick()
        self.api.submission_status = "finished"
        self.tick()
        self.tick()
        self.assertEqual(len(self.api.messages["m1"]["comments"]), 1)
        self.assertIn("Verdict:", self.api.messages["m1"]["comments"][0]["body"])
        self.assertEqual(self.api.submit_count, 1)

    def test_failed_notification_preserves_accepted_submission(self):
        self.api.publish_error = True
        self.tick()
        self.assertEqual(self.state.get("m1")["phase"], "polling")
        self.api.submission_status = "finished"
        self.tick()
        self.assertEqual(self.state.get("m1")["phase"], "publishing")
        self.api.publish_error = False
        self.tick()
        self.assertEqual(self.state.get("m1")["phase"], "done")
        self.assertEqual(self.api.submit_count, 1)

    def test_explicit_rate_limit_delays_then_retries_submission(self):
        self.api.submit_error = Retryable("rate limit", 120)
        self.tick()
        self.assertEqual(self.state.get("m1")["phase"], "queued")
        self.tick(60)
        self.assertEqual(self.api.submit_count, 1)
        self.api.submit_error = None
        self.tick(61)
        self.assertEqual(self.api.submit_count, 2)
        self.assertIn(SUBMITTED, self.tags())

    def test_timeout_does_not_resubmit(self):
        self.tick()
        self.tick(self.config.job_timeout + 1)
        self.assertEqual(self.state.get("m1")["phase"], "timeout")
        self.assertIn(TIMEOUT, self.tags())
        self.tick(10000)
        self.assertEqual(self.api.submit_count, 1)

    def test_waits_for_all_analyses_including_reverser(self):
        self.api.extra_analyses = [{"webid": "102", "analysis_type": "sandbox"},
                                   {"webid": "r-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "analysis_type": "reverser"}]
        self.finish()
        self.assertEqual(len(self.state.get("m1")["results"]), 3)

    def test_reverser_verdict_controls_overall_verdict_and_report_link(self):
        self.api.detection = "clean"
        self.api.reverser_detection = "malicious"
        self.api.extra_analyses = [{"webid": "r-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "analysis_type": "reverser"}]
        self.finish()
        self.assertEqual(self.state.get("m1")["verdict"], "malicious")
        self.assertEqual(self.api.messages["m1"]["category"], "THREAT")
        comment = self.api.messages["m1"]["comments"][-1]["body"]
        self.assertIn("Verdict: Malicious", comment)
        self.assertIn("Score: 95/100", comment)
        self.assertNotIn("/joereverser/", comment)

    def test_reverser_pending_prevents_early_publication(self):
        self.api.reverser_status = "running"
        self.api.extra_analyses = [{"webid": "r-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "analysis_type": "reverser"}]
        self.finish()
        self.assertEqual(self.state.get("m1")["phase"], "polling")
        self.assertEqual(self.api.messages["m1"]["comments"], [])
        self.api.reverser_status = "finished"
        self.tick()
        self.assertEqual(self.state.get("m1")["phase"], "done")
        self.assertEqual(len(self.api.messages["m1"]["comments"]), 1)
        self.assertNotIn("Joe Sandbox Completed", self.tags())

    def test_bare_reverser_uuid_uses_type_from_submission(self):
        webid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        self.api.extra_analyses = [{"webid": webid, "analysis_type": "reverser"}]
        self.finish()
        result = self.state.get("m1")["results"][-1]
        self.assertEqual(result["analysis_type"], "reverser")
        self.assertEqual(result["link"], "https://jbxcloud.joesecurity.org/joereverser/analysis/" + webid)
        self.assertEqual(self.api.messages["m1"]["comments"][-1]["body"].count("Report:"), 1)

    def test_only_one_final_comment_when_new_analyses_appear(self):
        self.tick()
        self.tick()
        self.api.extra_analyses = [{"webid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "analysis_type": "reverser"}]
        self.tick()
        self.assertEqual(self.api.messages["m1"]["comments"], [])
        self.api.submission_status = "finished"
        self.tick()
        self.assertEqual(len(self.api.messages["m1"]["comments"]), 1)
        self.assertIn("Verdict: Malicious", self.api.messages["m1"]["comments"][0]["body"])

    def test_failures_use_tags_without_discussion_comments(self):
        self.api.submit_error = ApiError("Definite submission failure")
        self.tick()
        self.tick()
        self.assertIn(ERROR, self.tags())
        self.assertEqual(self.api.messages["m1"]["comments"], [])

    def test_unlicensed_reverser_is_kept_in_state_without_expanding_comment(self):
        self.joe.reverser_available = False
        self.finish()
        self.assertTrue(self.state.get("m1")["reverser_unlicensed"])
        self.assertNotIn("not licensed", self.api.messages["m1"]["comments"][0]["body"])

    def test_does_not_finish_while_analysis_running(self):
        self.api.analysis_status = "running"
        self.finish()
        self.assertEqual(self.state.get("m1")["phase"], "polling")

    def test_completed_submission_with_no_analyses_waits(self):
        self.tick()
        self.joe.submission = Mock(return_value={"status": "finished", "analyses": []})
        self.tick()
        self.assertEqual(self.state.get("m1")["phase"], "polling")

    def test_resolved_or_unprocessed_messages_are_skipped(self):
        self.api.messages["m1"]["actionStatus"] = "RESOLVED"
        self.tick()
        self.assertEqual(self.api.submit_count, 0)
        self.api.messages["m1"]["actionStatus"] = "RECEIVED"
        self.api.messages["m1"]["pipelineStatus"] = "PROCESSING"
        self.tick(61)
        self.assertEqual(self.api.submit_count, 0)

    def test_in_flight_limit(self):
        self.api.messages["m2"] = {**self.api.messages["m1"], "id": "m2", "tags": [], "comments": []}
        with patch("joe_phisher.worker.MAX_IN_FLIGHT", 1):
            self.tick()
        self.assertEqual(self.api.submit_count, 1)
        self.assertEqual(self.state.get("m2")["phase"], "queued")

    def test_api_auth_failure_stops_worker_without_resubmitting(self):
        self.api.submit_error = FatalAuth("unauthorized")
        with self.assertRaises(FatalAuth):
            self.tick()
        self.assertEqual(self.state.get("m1")["phase"], "queued")


class ClientTests(unittest.TestCase):
    # Mock HTTP responses/adapters while exercising the production request-building code.
    def test_user_agent_identifies_integration_and_package_version(self):
        with open("pyproject.toml", "rb") as handle:
            release = tomllib.load(handle)["project"]["version"]
        self.assertEqual(__version__, release)
        session = requests.Session()
        self.addCleanup(session.close)
        transport = Transport(session=session)
        self.assertEqual(transport.session.headers["User-Agent"], f"JoeSandbox-PhishER/{release}")

    def response(self, status=200, body=None, headers=None):
        result = Mock(status_code=status, headers=headers or {})
        result.json.return_value = body if body is not None else {"data": {}}
        return result

    def transport(self, response):
        session = Mock()
        session.post.return_value = response
        return Transport(session=session), session

    def test_submission_timeout_is_ambiguous(self):
        transport, session = self.transport(None)
        session.post.side_effect = requests.Timeout("contains private data")
        with self.assertRaises(AmbiguousSubmission) as ctx:
            transport.post("https://api.example", submission=True)
        self.assertNotIn("private", str(ctx.exception))
        self.assertEqual(session.post.call_count, 1)

    def test_reverser_is_requested_by_default_and_can_be_disabled(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                api = FakeServices()
                joe = JoeSandbox(replace(Config(), enable_reverser=enabled), "test-key", api)
                joe.submit(b"test eml", "test-reference")
                self.assertEqual(api.calls[0][1]["data"]["analyze-on-reverser"], "1" if enabled else "0")
                self.assertEqual(joe.last_submission_reverser, enabled)

    def test_reverser_license_rejection_falls_back_once_and_is_remembered(self):
        rejected = {"errors": [{"code": 1, "message": "Joe Reverser is not enabled for your account"}]}
        transport, session = self.transport(None)
        session.post.side_effect = [self.response(400, rejected),
                                    self.response(200, {"data": {"submission_id": "s1"}}),
                                    self.response(200, {"data": {"submission_id": "s2"}})]
        joe = JoeSandbox(replace(Config(), enable_cache=True), "test-key", transport)
        self.assertEqual(joe.submit(b"unchanged eml bytes", "test-reference"), "s1")
        self.assertTrue(joe.last_submission_reverser_fallback)
        self.assertFalse(joe.last_submission_reverser)
        self.assertEqual(joe.submit(b"next eml", "next-reference"), "s2")
        calls = session.post.call_args_list
        self.assertEqual([c.kwargs["data"]["analyze-on-reverser"] for c in calls], ["1", "0", "0"])
        self.assertEqual(calls[0].kwargs["files"], calls[1].kwargs["files"])
        self.assertEqual([c.kwargs["data"]["report-cache"] for c in calls], ["1", "1", "1"])

    def test_reverser_fallback_never_runs_for_other_or_ambiguous_errors(self):
        cases = [(400, {"errors": [{"code": 1, "message": "Joe Reverser quota exhausted"}]}),
                 (400, {"errors": [{"code": 1, "message": "Joe Reverser is not enabled for your account"}],
                        "data": {"submission_id": "already-accepted"}}),
                 (403, {}), (503, {}), (200, {})]
        for status, body in cases:
            with self.subTest(status=status, body=body):
                transport, session = self.transport(self.response(status, body))
                with self.assertRaises(ApiError):
                    JoeSandbox(Config(), "test-key", transport).submit(b"eml", "reference")
                self.assertEqual(session.post.call_count, 1)

    def test_reverser_fallback_timeout_is_not_retried_again(self):
        rejected = {"errors": [{"code": 1, "message": "Joe Reverser is not enabled for your account"}]}
        transport, session = self.transport(None)
        session.post.side_effect = [self.response(400, rejected), requests.Timeout()]
        with self.assertRaises(AmbiguousSubmission):
            JoeSandbox(Config(), "test-key", transport).submit(b"eml", "reference")
        self.assertEqual(session.post.call_count, 2)

    def test_submission_info_includes_existing_reverser_analyses(self):
        api = FakeServices()
        JoeSandbox(replace(Config(), enable_reverser=False), "test-key", api).submission("s1")
        self.assertEqual(api.calls[0][1]["data"]["include-reverser-analyses"], "1")

    def test_read_timeout_is_retryable(self):
        transport, session = self.transport(None)
        session.post.side_effect = requests.Timeout()
        with self.assertRaises(Retryable):
            transport.post("https://api.example")

    def test_503_submission_is_ambiguous(self):
        transport, _ = self.transport(self.response(503))
        with self.assertRaises(AmbiguousSubmission):
            transport.post("https://api.example", submission=True)

    def test_invalid_json_after_submission_is_ambiguous(self):
        response = self.response()
        response.json.side_effect = ValueError()
        transport, _ = self.transport(response)
        with self.assertRaises(AmbiguousSubmission):
            transport.post("https://api.example", submission=True)

    def test_429_honors_retry_after(self):
        transport, _ = self.transport(self.response(429, headers={"Retry-After": "123"}))
        with self.assertRaises(Retryable) as ctx:
            transport.post("https://api.example", submission=True)
        self.assertEqual(ctx.exception.retry_after, 123)

    def test_redirect_never_followed(self):
        transport, session = self.transport(self.response(302))
        with self.assertRaises(ApiError):
            transport.post("https://api.example")
        self.assertFalse(session.post.call_args.kwargs["allow_redirects"])

    def test_proxy_routing_for_both_clients_ignores_environment(self):
        for proxy in ("", "http://proxy.example:3128", "https://proxy.example:8443",
                      "http://example-user:example-password@proxy.example:3128"):
            with self.subTest(proxy=bool(proxy)):
                config = replace(Config(), proxy_url=proxy)
                sessions = [requests.Session(), requests.Session()]
                adapters = []
                bodies = [{"data": {"phisherMessage": {"id": "m1"}}},
                          {"data": {"webid": "101"}}]
                for session, body in zip(sessions, bodies):
                    response = requests.Response()
                    response.status_code = 200
                    response._content = json.dumps(body).encode()
                    adapter = Mock(spec=requests.adapters.BaseAdapter)
                    adapter.send.return_value = response
                    session.mount("https://", adapter)
                    adapters.append(adapter)
                    self.addCleanup(session.close)
                with (patch.dict("os.environ", {"HTTPS_PROXY": "http://ignored.example:9999", "NO_PROXY": "*"}),
                      patch("joe_phisher.clients.requests.Session", side_effect=sessions)):
                    Phisher(config, "test-token").message("m1")
                    JoeSandbox(config, "test-key").analysis("101")
                for adapter in adapters:
                    request_options = adapter.send.call_args.kwargs
                    self.assertEqual(adapter.send.call_args.args[0].headers["User-Agent"],
                                     f"JoeSandbox-PhishER/{__version__}")
                    self.assertEqual(request_options["proxies"], {"http": proxy, "https": proxy} if proxy else {})
                    self.assertIs(request_options["verify"], True)

    def test_proxy_connection_failure_does_not_expose_credentials(self):
        transport, session = self.transport(None)
        session.post.side_effect = requests.exceptions.ProxyError("example-user:example-password@proxy.example")
        with self.assertRaises(AmbiguousSubmission) as context:
            transport.post("https://api.example", submission=True)
        self.assertNotIn("example-password", str(context.exception))
        self.assertNotIn("proxy.example", str(context.exception))

    def test_proxy_authentication_failure_stops_processing(self):
        transport, _ = self.transport(self.response(407))
        with self.assertRaises(FatalAuth) as context:
            transport.post("https://api.example", submission=True)
        self.assertIn("Proxy authentication", str(context.exception))

    def test_eml_download_preserves_bytes_and_omits_api_authorization(self):
        eml = b"From: sender@example.test\r\nSubject: Test\r\n\r\nBinary body: \xff\x00\r\n"
        session = requests.Session()
        session.headers["Authorization"] = "Bearer example-api-token"
        self.addCleanup(session.close)
        response = requests.Response()
        response.status_code = 200
        response._content = eml
        response._content_consumed = True
        adapter = Mock(spec=requests.adapters.BaseAdapter)
        adapter.send.return_value = response
        session.mount("https://", adapter)
        proxy = "http://proxy.example:3128"
        transport = Transport(session=session, proxy_url=proxy)
        self.assertEqual(transport.download("https://download.example/test.eml?sig=private"), eml)
        prepared = adapter.send.call_args.args[0]
        self.assertEqual(prepared.method, "GET")
        self.assertEqual(prepared.headers["User-Agent"], f"JoeSandbox-PhishER/{__version__}")
        self.assertNotIn("Authorization", prepared.headers)
        self.assertEqual(adapter.send.call_args.kwargs["proxies"], {"http": proxy, "https": proxy})

    def test_multipart_upload_contains_original_email_and_attachment(self):
        # Inspect the encoded HTTP body to prove that the EML survives the file upload intact.
        eml = (b"From: sender@example.test\r\nMIME-Version: 1.0\r\n"
               b'Content-Type: multipart/mixed; boundary="original-boundary"\r\n\r\n'
               b"--original-boundary\r\nContent-Type: text/plain\r\n\r\nTest body\r\n"
               b"--original-boundary\r\nContent-Type: application/octet-stream\r\n"
               b'Content-Disposition: attachment; filename="test.bin"\r\n'
               b"Content-Transfer-Encoding: base64\r\n\r\nAAECAw==\r\n--original-boundary--\r\n")
        session = requests.Session()
        self.addCleanup(session.close)
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"data":{"submission_id":"s1"}}'
        adapter = Mock(spec=requests.adapters.BaseAdapter)
        adapter.send.return_value = response
        session.mount("https://", adapter)
        transport = Transport(session=session)
        client = JoeSandbox(replace(Config(), accept_tac=True), "test-key", transport)
        self.assertEqual(client.submit(eml, "test-reference"), "s1")
        prepared = adapter.send.call_args.args[0]
        self.assertIn("multipart/form-data; boundary=", prepared.headers["Content-Type"])
        self.assertIn(b'name="sample"; filename="message.eml"', prepared.body)
        self.assertIn(b"Content-Type: message/rfc822", prepared.body)
        self.assertIn(eml, prepared.body)
        self.assertNotIn(b'name="sample-url"', prepared.body)

    def test_eml_download_size_limit_and_empty_response(self):
        for headers, chunks in (({"Content-Length": "5"}, [b"12345"]),
                                ({}, [b"123", b"45"]), ({}, [])):
            with self.subTest(headers=headers, chunks=chunks):
                response = self.response(headers=headers)
                response.iter_content.return_value = chunks
                transport, session = self.transport(response)
                session.get.return_value = response
                with patch("joe_phisher.clients.MAX_EML_BYTES", 4), self.assertRaises(ApiError):
                    transport.download("https://download.example/test.eml")
                response.close.assert_called_once()

    def test_eml_download_errors_are_retryable_and_redirects_rejected(self):
        for status, error in ((403, Retryable), (404, Retryable), (429, Retryable),
                              (503, Retryable), (302, ApiError), (407, FatalAuth)):
            with self.subTest(status=status):
                response = self.response(status, headers={"Retry-After": "120"})
                transport, session = self.transport(response)
                session.get.return_value = response
                with self.assertRaises(error):
                    transport.download("https://download.example/test.eml")
                response.close.assert_called_once()
                self.assertFalse(session.get.call_args.kwargs["allow_redirects"])

    def test_eml_download_transport_errors_are_redacted(self):
        transport, session = self.transport(None)
        session.get.side_effect = requests.Timeout("https://download.example/?secret=test-value")
        with self.assertRaises(Retryable) as context:
            transport.download("https://download.example/?secret=test-value")
        self.assertNotIn("test-value", str(context.exception))

    def test_invalid_eml_download_urls_never_requested(self):
        transport = Mock()
        client = Phisher(Config(), "test-token", transport)
        for url in ("file:///tmp/email.eml", "http://example.test/email", "https://user:pass@example.test/email"):
            with self.subTest(url=url), self.assertRaises(ApiError):
                client.download_email(url)
        transport.download.assert_not_called()

    def test_submission_rejects_url_instead_of_eml_bytes(self):
        transport = Mock()
        client = JoeSandbox(replace(Config(), accept_tac=True), "test-key", transport)
        with self.assertRaises(ApiError):
            client.submit("https://download.example/test.eml", "test-reference")
        transport.post.assert_not_called()

    def test_auth_and_error_bodies_not_exposed(self):
        transport, _ = self.transport(self.response(403, {"error": "private token"}))
        with self.assertRaises(FatalAuth) as ctx:
            transport.post("https://api.example")
        self.assertNotIn("private", str(ctx.exception))

    def test_nested_graphql_errors_are_rejected(self):
        transport = Mock()
        transport.post.return_value = {"data": {"phisherTagsCreate": {"errors": [{"reason": "secret"}]}}}
        client = Phisher(Config(), "token", transport)
        with self.assertRaises(ApiError) as ctx:
            client.tags("id", [MALICIOUS])
        self.assertNotIn("secret", str(ctx.exception))

    def test_graphql_top_level_errors_rejected(self):
        transport = Mock()
        transport.post.return_value = {"errors": [{"message": "secret"}]}
        with self.assertRaises(ApiError):
            Phisher(Config(), "token", transport).message("id")

    def test_legacy_comment_reference_is_recognized_after_renaming(self):
        api = FakeServices()
        api.messages["m1"]["comments"] = [{"body": "Old result [joe-phisher:old-job:result]"}]
        client = Phisher(Config(), "test-token", api)
        client.ensure_comment("m1", "New result", "[KnowBe4-PhishER:old-job:result]")
        self.assertEqual(len(api.messages["m1"]["comments"]), 1)
        self.assertEqual(len(api.calls), 1)

    def test_report_cache_defaults_off_and_can_be_enabled(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                api = FakeServices()
                JoeSandbox(replace(Config(), enable_cache=enabled), "test-key", api).submit(b"test eml", "test-reference")
                self.assertEqual(api.calls[0][1]["data"]["report-cache"], "1" if enabled else "0")
        self.assertFalse(Config().enable_cache)

    def test_compact_comment_uses_submission_link_and_highest_score(self):
        job = {"outcome": "done", "submission_id": "6133578", "verdict": "malicious", "results": [
            {"webid": "5939343", "analysis_type": "sandbox", "score": 0, "threatname": "Unknown",
             "link": "https://jbxcloud.joesecurity.org/analysis/5939343/0/html"},
            {"webid": "5939345", "analysis_type": "sandbox", "score": 48, "threatname": "Emotet",
             "link": "https://jbxcloud.joesecurity.org/analysis/5939345/0/html"},
            {"webid": "reverser-id", "analysis_type": "reverser", "score": 85, "threatname": "emotet",
             "link": "https://jbxcloud.joesecurity.org/joereverser/analysis/reverser-id"},
        ]}
        self.assertEqual(final_comment(job),
                         "Joe Sandbox Cloud Verdict: Malicious\nThreat name: Emotet\nScore: 85/100\n"
                         "Report: https://jbxcloud.joesecurity.org/submission/6133578")
        self.assertIn("Report: https://cloud.example.test/submission/6133578",
                      final_comment(job, "https://cloud.example.test/"))

    def test_compact_comment_is_not_duplicated_after_whitespace_normalization(self):
        api = FakeServices()
        body = "Joe Sandbox Cloud Verdict: Clean\nThreat name: Not reported\nScore: 0/100\nReport: https://example.test/1"
        api.messages["m1"]["comments"] = [{"body": " ".join(body.split())}]
        Phisher(Config(), "test-token", api).ensure_comment("m1", body, "[KnowBe4-PhishER:job:result]")
        self.assertEqual(len(api.messages["m1"]["comments"]), 1)
        self.assertEqual(len(api.calls), 1)

    def test_phisher_scope_and_variables(self):
        api = FakeServices()
        Phisher(Config(), "test-token", api).message("m1")
        _, request = api.calls[0]
        self.assertEqual(request["params"], {"scope": "phisher"})
        self.assertEqual(request["headers"], {"Authorization": "Bearer test-token"})
        self.assertEqual(request["json"]["variables"], {"id": "m1"})

    @patch("joe_phisher.clients.MAX_DISCOVERY_PAGES", 1)
    def test_pagination_continues_between_bounded_scans(self):
        config = Config()
        transport = Mock()
        transport.post.side_effect = [
            {"data": {"phisherMessages": {"nodes": [
                {"id": "processing-message", "pipelineStatus": "PROCESSING", "actionStatus": "RECEIVED", "tags": []}
            ], "pagination": {"pages": 2, "nextPageKey": "next"}}}},
            {"data": {"phisherMessages": {"nodes": [], "pagination": {"pages": 2}}}},
        ]
        client = Phisher(config, "token", transport)
        list(client.discover())
        list(client.discover())
        variables = transport.post.call_args.kwargs["json"]["variables"]
        self.assertEqual(variables["page"], 2)
        self.assertEqual(variables["cursor"], "next")
        self.assertEqual(client.discovery_page, 1)

    def test_empty_search_with_null_page_count_stops_cleanly(self):
        transport = Mock()
        transport.post.return_value = {"data": {"phisherMessages": {
            "nodes": [], "pagination": {"page": 1, "pages": None, "nextPageKey": None, "totalCount": 0}}}}
        client = Phisher(Config(), "test-token", transport)
        self.assertEqual(list(client.discover()), [])
        self.assertEqual(client.discovery_page, 1)
        self.assertIsNone(client.discovery_cursor)
        self.assertEqual(transport.post.call_count, 1)

    def test_verdicts_use_worst_explicit_detection_and_preserve_unknown(self):
        self.assertEqual(aggregate_verdict(["clean", "suspicious", "malicious"]), "malicious")
        self.assertEqual(aggregate_verdict(["clean", "unknown"]), "unknown")
        info = {"webid": "1", "score": 100, "runs": [{"detection": "clean"}]}
        self.assertEqual(analysis_summary(info, "link")["verdict"], "clean")
        self.assertEqual(analysis_summary({"webid": "1", "score": 100}, "link")["verdict"], "unknown")

    def test_joe_rejects_mismatched_analysis_id(self):
        transport = Mock()
        transport.post.return_value = {"data": {"webid": "wrong"}}
        with self.assertRaises(ApiError):
            JoeSandbox(Config(), "key", transport).analysis("wanted")

    def test_threat_name_is_rendered_on_one_line(self):
        result = analysis_summary({"webid": "1", "threatname": "Emotet\r\n  Trojan"}, "link")
        self.assertEqual(result["threatname"], "Emotet Trojan")

    def test_missing_threat_name_is_reported_and_old_results_still_render(self):
        for value in (None, "", "  ", 123):
            with self.subTest(value=value):
                result = analysis_summary({"webid": "1", "threatname": value}, "link")
                self.assertEqual(result["threatname"], "")
                job = {"outcome": "done", "verdict": "unknown", "finished_at": 0,
                       "submission_id": "s1", "job_id": "job1", "results": [result]}
                self.assertIn("Threat name: Not reported", final_comment(job))
                del result["threatname"]
                self.assertIn("Threat name: Not reported", final_comment(job))

    def test_failed_run_does_not_become_clean(self):
        result = analysis_summary({"webid": "1", "detection": "clean", "runs": [
            {"detection": "clean", "error": "Run failed", "score": 0}]}, "link")
        self.assertEqual(result["verdict"], "unknown")
        self.assertEqual(result["run_errors"], 1)

    def test_malicious_verdict_survives_partial_run_failure(self):
        result = analysis_summary({"webid": "1", "detection": "malicious", "runs": [
            {"detection": "clean", "error": "Run failed", "score": 0},
            {"detection": "malicious", "error": "", "score": 100}]}, "link")
        self.assertEqual(result["verdict"], "malicious")
        self.assertEqual(result["run_errors"], 1)

    def test_joe_requires_id_after_submission(self):
        transport = Mock()
        transport.post.return_value = {"data": {}}
        with self.assertRaises(AmbiguousSubmission):
            JoeSandbox(replace(Config(), accept_tac=True), "key", transport).submit(b"From: example@example.test\r\n\r\ntest", "marker")

    def test_retry_after_date(self):
        self.assertGreater(retry_delay("Wed, 01 Jan 2098 00:00:00 GMT"), 60)
        self.assertEqual(retry_delay("invalid"), 60)


class ConfigTests(unittest.TestCase):
    # Use disposable TOML files and fabricated credentials for validation and CLI tests.
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "config.toml"

    def test_shipped_defaults(self):
        config = Config.read("config.example.toml")
        self.assertEqual(config.ingestion_tag, "")
        self.assertTrue(config.set_category_on_malicious)
        self.assertTrue(config.accept_tac)
        self.assertTrue(config.enable_reverser)
        self.assertFalse(config.enable_cache)

    def test_cache_setting_defaults_off_and_requires_boolean(self):
        self.path.write_text("[joe_sandbox]\n")
        self.assertFalse(Config.read(str(self.path)).enable_cache)
        for literal, expected in (("false", False), ("true", True)):
            with self.subTest(literal=literal):
                self.path.write_text("[joe_sandbox]\nenable_cache = " + literal + "\n")
                self.assertEqual(Config.read(str(self.path)).enable_cache, expected)
        for literal in ('"false"', "0", "1"):
            with self.subTest(literal=literal):
                self.path.write_text("[joe_sandbox]\nenable_cache = " + literal + "\n")
                with self.assertRaisesRegex(ValueError, "joe_sandbox.enable_cache must be a boolean"):
                    Config.read(str(self.path))

    def test_reverser_setting_must_be_boolean(self):
        self.path.write_text('[joe_sandbox]\nenable_reverser = false\n')
        self.assertFalse(Config.read(str(self.path)).enable_reverser)
        self.path.write_text('[joe_sandbox]\nenable_reverser = "false"\n')
        with self.assertRaises(ValueError):
            Config.read(str(self.path))

    def test_unknown_execution_options_rejected(self):
        self.path.write_text('[joe_sandbox.options]\nsystems = ["w10"]\n')
        with self.assertRaises(ValueError):
            Config.read(str(self.path))

    def test_plain_http_rejected(self):
        self.path.write_text('[joe_sandbox]\ncloud_api_url = "http://example.com/api"\n')
        with self.assertRaises(ValueError):
            Config.read(str(self.path))

    def test_proxy_config_accepts_http_https_and_credentials(self):
        for value in ("", "http://proxy.example:3128", "https://proxy.example:8443",
                      "http://example-user:example-password@proxy.example:3128"):
            with self.subTest(configured=bool(value)):
                self.path.write_text('[connection]\nproxy_url = ' + json.dumps(value) + '\n')
                config = Config.read(str(self.path))
                self.assertEqual(config.proxy_url, value)
                self.assertNotIn("example-password", repr(config))

    def test_invalid_proxy_config_is_rejected_without_echoing_url(self):
        values = [123, "socks5://proxy.example:1080", "http://", "http://proxy.example:70000",
                  "http://proxy.example:not-a-port", "http://proxy.example/path",
                  "http://proxy.example?query=1", "http://proxy.example#fragment", " http://proxy.example",
                  "http://example-user:example-password@[invalid", "http://proxy.example\n"]
        for value in values:
            with self.subTest(value_type=type(value).__name__):
                self.path.write_text('[connection]\nproxy_url = ' + json.dumps(value) + '\n')
                with self.assertRaises(ValueError) as context:
                    Config.read(str(self.path))
                self.assertNotIn("example-password", str(context.exception))

    def test_managed_tag_cannot_be_trigger(self):
        self.path.write_text('[knowbe4]\nrequired_tag = "Joe Sandbox Malicious"\n')
        with self.assertRaises(ValueError):
            Config.read(str(self.path))

    def write_credentials(self):
        self.path.write_text(
            '[knowbe4]\nproduct_api_token = "test-inline-phisher"\n'
            '[joe_sandbox]\ncloud_api_key = "test-inline-joe"\n'
            f'[service]\ndatabase_path = {json.dumps(str(self.path.parent / "state.sqlite3"))}\n')

    def test_inline_credentials_loaded_and_hidden_in_repr(self):
        self.write_credentials()
        config = Config.read(str(self.path))
        self.assertEqual(config.phisher_api_token, "test-inline-phisher")
        self.assertEqual(config.joe_api_key, "test-inline-joe")
        self.assertNotIn("test-inline-phisher", repr(config))
        self.assertNotIn("test-inline-joe", repr(config))

    def test_inline_credentials_are_used_by_runtime(self):
        self.write_credentials()
        with (patch("sys.argv", ["joe-phisher", "--config", str(self.path), "run"]),
              patch.dict("os.environ", {"PHISHER_API_TOKEN": "unused", "JOE_API_KEY": "unused"}),
              patch("joe_phisher.__main__.Phisher") as phisher,
              patch("joe_phisher.__main__.JoeSandbox") as joe,
              patch("joe_phisher.__main__.Worker"),
              patch("joe_phisher.__main__.threading.Event") as event,
              patch("joe_phisher.__main__.signal.signal")):
            event.return_value.is_set.return_value = True
            self.assertEqual(main(), 0)
        self.assertEqual(phisher.call_args.args[1], "test-inline-phisher")
        self.assertEqual(joe.call_args.args[1], "test-inline-joe")

    def test_credentials_require_strings_without_line_breaks(self):
        for value in ('123', '"""line1\nline2"""', '" padded "'):
            with self.subTest(value=value):
                self.path.write_text(f'[knowbe4]\nproduct_api_token = {value}\n')
                with self.assertRaises(ValueError):
                    Config.read(str(self.path))

    def test_local_run_can_override_state_path(self):
        self.write_credentials()
        alternate = self.path.parent / "local-state.sqlite3"
        with (patch("sys.argv", ["joe-phisher", "--config", str(self.path),
                                 "--state-path", str(alternate), "run"]),
              patch("joe_phisher.__main__.Phisher"),
              patch("joe_phisher.__main__.JoeSandbox"),
              patch("joe_phisher.__main__.Worker") as worker,
              patch("joe_phisher.__main__.threading.Event") as event,
              patch("joe_phisher.__main__.signal.signal")):
            event.return_value.is_set.return_value = True
            self.assertEqual(main(), 0)
        self.assertEqual(worker.call_args.args[0].state_path, str(alternate))
        self.assertTrue(alternate.exists())

    def test_check_config_requires_credentials_and_does_not_echo_them(self):
        self.path.write_text("")
        with patch("sys.argv", ["joe-phisher", "--config", str(self.path), "check-config"]):
            with self.assertLogs(level="ERROR"):
                self.assertEqual(main(), 1)
        self.write_credentials()
        with (patch("sys.argv", ["joe-phisher", "--config", str(self.path), "check-config"]),
              patch("sys.stdout", new_callable=io.StringIO) as output):
            self.assertEqual(main(), 0)
        self.assertEqual(output.getvalue(), "Configuration valid. No API calls made.\n")

    def test_state_instance_lock(self):
        path = self.temp.name + "/state.sqlite3"
        with instance_lock(path):
            with self.assertRaises(RuntimeError):
                with instance_lock(path):
                    pass


if __name__ == "__main__":
    unittest.main()
