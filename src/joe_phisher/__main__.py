# Command-line lifecycle: read settings, lock state, then run or inspect the worker.
import argparse
import json
import logging
import signal
import threading
from dataclasses import replace

from .clients import ApiError, JoeSandbox, Phisher
from .config import Config
from .state import State, instance_lock
from .worker import Worker


def parser():
    # Recovery and status are explicit commands so normal startup never resubmits old jobs.
    result = argparse.ArgumentParser(description="Joe Sandbox Cloud / KnowBe4 PhishER connector")
    result.add_argument("--config", default="/app/config.toml")
    result.add_argument("--state-path", help="Override the database path for a local run")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("run", help="Discover emails, submit, poll and publish")
    commands.add_parser("check-config", help="Validate configuration only; no API calls")
    commands.add_parser("status", help="List durable local jobs; no API calls")
    attach = commands.add_parser("attach-submission", help="Recover a reviewed ambiguous submission")
    attach.add_argument("message_id")
    attach.add_argument("submission_id")
    return result


def main():
    args = parser().parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        config = Config.read(args.config)
        if args.state_path:
            config = replace(config, state_path=args.state_path)
        if args.command in {"run", "check-config"} and (not config.phisher_api_token or not config.joe_api_key):
            raise ValueError("Set knowbe4.product_api_token and joe_sandbox.cloud_api_key to non-empty strings in the TOML configuration")
        if args.command == "check-config":
            print("Configuration valid. No API calls made.")
            return 0
        with instance_lock(config.state_path):
            # Keep the lock for the entire command, including manual recovery operations.
            state = State(config.state_path)
            try:
                if args.command == "status":
                    for job in state.jobs():
                        print(json.dumps({key: job.get(key) for key in
                                          ("message_id", "phase", "job_id", "submission_id", "verdict", "error")}))
                    return 0
                if args.command == "attach-submission":
                    # The operator supplies an existing Joe ID after checking its association.
                    # This command validates access to that ID and never creates a submission.
                    job = state.get(args.message_id)
                    if not job or job["phase"] not in {"blocked", "timeout", "publishing", "submitting"}:
                        raise ValueError("Only an interrupted, blocked or timed-out job can be recovered")
                    if job["phase"] == "publishing" and job.get("outcome") not in {"blocked", "timeout"}:
                        raise ValueError("This job does not require submission recovery")
                    if job.get("submission_id") and job["submission_id"] != args.submission_id:
                        raise ValueError("This job already has a different submission ID")
                    if not config.joe_api_key:
                        raise ValueError("Set joe_sandbox.cloud_api_key to a non-empty string in the TOML configuration")
                    joe = JoeSandbox(config, config.joe_api_key)
                    joe.submission(args.submission_id)  # Validate access; never creates a submission.
                    import time
                    job.update(phase="polling", submission_id=args.submission_id,
                               submitted_at=time.time(), next_attempt=0)
                    for key in ("outcome", "error", "finished_at"):
                        job.pop(key, None)
                    job["steps"] = [step for step in job["steps"] if step not in {"final_comment", "final_tag"}]
                    # Recovery uses a new result marker so the old failure comment is preserved.
                    job["job_id"] += "r"
                    state.save(job)
                    print("Submission attached. Start the connector to resume polling.")
                    return 0
                phisher = Phisher(config, config.phisher_api_token)
                joe = JoeSandbox(config, config.joe_api_key)
                worker = Worker(config, state, phisher, joe)
                stop = threading.Event()
                # Signal handlers request shutdown; they do not interrupt a state update halfway.
                for sig in (signal.SIGINT, signal.SIGTERM):
                    signal.signal(sig, lambda *_: stop.set())
                logging.info("Connector started; ingestion=%s", "all eligible emails" if not config.ingestion_tag else "tag-filtered")
                while not stop.is_set():
                    worker.tick()
                    # Waiting on the event allows SIGTERM to wake the main loop promptly.
                    stop.wait(1)
            finally:
                # Flush/close SQLite even when authentication or another API operation fails.
                state.close()
    except (ApiError, ValueError, OSError, RuntimeError) as exc:
        # Exception classes above only contain our safe messages, except OS paths.
        logging.error("Connector stopped: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
