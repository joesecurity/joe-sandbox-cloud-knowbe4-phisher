"""Discovery, submission, polling and idempotent PhishER publication."""

import logging
import time

from .clients import (AmbiguousSubmission, ApiError, FatalAuth, Retryable,
                      aggregate_verdict, analysis_summary)
from .comments import final_comment, marker
from .config import ERROR, MALICIOUS, REVIEW, SUBMITTED, SUSPICIOUS, TIMEOUT
from .state import TERMINAL

LOG = logging.getLogger(__name__)
POLL_INTERVAL = 30
MAX_IN_FLIGHT = 2
MAX_QUEUE = 1000


class Worker:
    def __init__(self, config, state, phisher, joe, clock=time.time):
        self.config, self.state, self.phisher, self.joe, self.clock = config, state, phisher, joe, clock
        self.next_discovery = 0
        self.pause_until = 0
        state.recover()

    def finish(self, job, outcome, error=None):
        # Save the outcome before publishing so a PhishER outage cannot lose completed results.
        job.update(phase="publishing", outcome=outcome, finished_at=self.clock())
        if error:
            job["error"] = error
        self.state.save(job)

    def step(self, job, name, action):
        # Checkpoint successful writes; the client helpers handle retries of uncertain writes.
        if name not in job["steps"]:
            action()
            job["steps"].append(name)
            self.state.save(job)

    def submit(self, job):
        message = self.phisher.message(job["message_id"])
        if not self.phisher.eligible(message):
            job["phase"] = "skipped"
            self.state.save(job)
            return
        if not message.get("rawUrl"):
            raise ApiError("PhishER did not provide the raw email download URL")
        # Download before recording submission intent: a failed GET is safe to retry.
        eml = self.phisher.download_email(message["rawUrl"])
        # Commit before the network call. A crash here must never cause an automatic resubmit.
        job["phase"] = "submitting"
        self.state.save(job)
        try:
            submission_id = self.joe.submit(eml, marker(job, "submission"))
        except FatalAuth:
            job["phase"] = "queued"
            self.state.save(job)
            raise
        except Retryable:
            # An explicit 429 rejected the submission, so it is safe to retry later.
            job["phase"] = "queued"
            self.state.save(job)
            raise
        finally:
            del eml
        job.update(phase="polling", submission_id=submission_id, submitted_at=self.clock(),
                   reverser_requested=getattr(self.joe, "last_submission_reverser", False),
                   reverser_unlicensed=getattr(self.joe, "last_submission_reverser_fallback", False))
        self.state.save(job)
        LOG.info("Submission accepted message=%s submission=%s", job["message_id"], submission_id)

    def notify_submitted(self, job):
        # Track acceptance through tags only; discussion receives completed results only.
        message_id = job["message_id"]
        self.step(job, "submitted_tag", lambda: self.phisher.tags(message_id, [SUBMITTED]))
        if self.config.ingestion_tag:
            self.step(job, "remove_request_tag", lambda: self.phisher.tags(
                message_id, [self.config.ingestion_tag], delete=True))

    def notify_pending(self, job):
        try:
            self.notify_submitted(job)
        except (FatalAuth, Retryable):
            raise
        except ApiError as exc:
            LOG.error("Submitted notification failed message=%s reason=%s", job["message_id"], exc)

    def poll(self, job):
        # Fetch Joe's state even if PhishER is temporarily unavailable.
        submission = self.joe.submission(job["submission_id"])
        status = str(submission.get("status", "")).lower()
        if status in {"failed", "error", "canceled", "cancelled"}:
            raise ApiError("Joe Sandbox reported a failed or cancelled submission")
        analyses = [entry for entry in submission.get("analyses") or []
                    if entry.get("analysis_type", "sandbox") in {"sandbox", "reverser"}]
        analysis_types = {str(entry["webid"]): entry.get("analysis_type", "sandbox")
                          for entry in analyses if entry.get("webid") is not None}
        links = [(str(entry["webid"]), self.joe.report_link(entry["webid"], entry.get("analysis_type")))
                 for entry in analyses if entry.get("webid") is not None]
        complete = status == "finished" and bool(links)
        results = []
        if complete:
            # Submission completion alone is insufficient: all returned analyses must be ready.
            for webid, link in links:
                info = self.joe.analysis(webid)
                if str(info.get("status", "")).lower() in {"failed", "error", "canceled", "cancelled"}:
                    raise ApiError("Joe Sandbox reported a failed analysis")
                if str(info.get("status", "")).lower() != "finished":
                    complete = False
                    break
                results.append(analysis_summary(info, link, analysis_types[webid]))
        if complete:
            job["results"] = results
            job["verdict"] = aggregate_verdict(result["verdict"] for result in results)
            self.finish(job, "done")
        else:
            if self.clock() - job["submitted_at"] >= self.config.job_timeout:
                self.finish(job, "timeout", "Timed out waiting for Joe Sandbox results; analysis may still finish in Joe Cloud")
            self.notify_pending(job)

    def publish(self, job):
        message_id, outcome = job["message_id"], job["outcome"]
        if job.get("submission_id"):
            self.notify_submitted(job)
        if outcome == "done":
            # Modify only our verdict tags; preserve all customer tags.
            tag = {"malicious": MALICIOUS, "suspicious": SUSPICIOUS}.get(job["verdict"])
            remove = [candidate for candidate in (MALICIOUS, SUSPICIOUS, ERROR, TIMEOUT, REVIEW) if candidate != tag]
            self.step(job, "remove_stale_verdict", lambda: self.phisher.tags(message_id, remove, delete=True))
            if tag:
                self.step(job, "verdict_tag", lambda: self.phisher.tags(message_id, [tag]))
            if job["verdict"] == "malicious" and self.config.set_category_on_malicious:
                self.step(job, "threat_category", lambda: self.phisher.mark_threat(message_id))
        else:
            status_tag = {"error": ERROR, "timeout": TIMEOUT, "blocked": REVIEW}[outcome]
        if outcome == "done":
            self.step(job, "final_comment", lambda: self.phisher.ensure_comment(
                message_id, final_comment(job, self.config.joe_report_url), marker(job, "result")))
        else:
            # Failures are represented only by tags; successful results get a comment.
            self.step(job, "final_tag", lambda: self.phisher.tags(message_id, [status_tag]))
        job["phase"] = outcome
        self.state.save(job)
        LOG.info("Job finished message=%s state=%s", message_id, outcome)

    def tick(self):
        now = self.clock()
        # A service rate limit pauses discovery and job processing until the retry deadline.
        if now < self.pause_until:
            return
        if now >= self.next_discovery:
            self.next_discovery = now + self.config.discovery_interval
            try:
                active = sum(job["phase"] not in TERMINAL for job in self.state.jobs())
                for message_id in self.phisher.discover():
                    if active >= MAX_QUEUE:
                        break
                    active += self.state.enqueue(message_id, now)
            except FatalAuth:
                raise
            except Retryable as exc:
                self.pause_until = now + exc.retry_after
                LOG.warning("Discovery delayed: %s", exc)
                return
            except ApiError as exc:
                LOG.error("Discovery failed: %s", exc)
        jobs = self.state.jobs()
        in_flight = sum(job["phase"] in {"submitting", "polling"} for job in jobs)
        # Publish/poll accepted work before starting additional jobs.
        for job in sorted(jobs, key=lambda job: job["phase"] == "queued"):
            phase = job["phase"]
            if phase in TERMINAL or job.get("next_attempt", 0) > now:
                continue
            if phase == "queued" and in_flight >= MAX_IN_FLIGHT:
                continue
            try:
                if phase == "queued":
                    if now - job["created"] >= self.config.job_timeout:
                        self.finish(job, "timeout", "Timed out in the local queue before submission")
                    else:
                        self.submit(job)
                        if job["phase"] == "polling":
                            in_flight += 1
                            self.notify_pending(job)
                elif phase == "polling":
                    if now - job["submitted_at"] >= self.config.job_timeout:
                        self.finish(job, "timeout", "Timed out waiting for Joe Sandbox results; analysis may still finish in Joe Cloud")
                    else:
                        self.poll(job)
                if job["phase"] == "publishing":
                    self.publish(job)
            except FatalAuth:
                raise
            except AmbiguousSubmission as exc:
                self.finish(job, "blocked", str(exc))
            except Retryable as exc:
                job["next_attempt"] = now + exc.retry_after
                # Keep the current phase so the next attempt resumes the same operation.
                self.state.save(job)
                self.pause_until = now + exc.retry_after
                LOG.warning("Retry delayed message=%s reason=%s", job["message_id"], exc)
                return
            except ApiError as exc:
                if job["phase"] == "publishing":
                    # Preserve a valid analysis result when only writing back to PhishER fails.
                    LOG.error("Publication failed message=%s reason=%s", job["message_id"], exc)
                else:
                    self.finish(job, "error", str(exc))
            job["next_attempt"] = now + POLL_INTERVAL
            self.state.save(job)
