"""Exercise the complete worker with local HTTPS PhishER and optional live Joe Cloud."""

import argparse
import hashlib
import json
import logging
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import SMTP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from joe_phisher.clients import JoeSandbox, Phisher, Transport
from joe_phisher.comments import final_comment
from joe_phisher.config import COMPLETED, MALICIOUS, SUBMITTED, SUSPICIOUS, Config
from joe_phisher.state import State, instance_lock
from joe_phisher.worker import Worker


def write_json(path, value):
    # Save only test metadata and synthetic messages; configuration and keys stay out.
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def create_email(directory):
    message_id = uuid.uuid4().hex
    attachment = f"Harmless Joe connector test attachment. Reference: {message_id}\r\n".encode()
    message = EmailMessage(policy=SMTP)
    message["From"] = "sender@example.invalid"
    message["To"] = "recipient@example.invalid"
    message["Subject"] = f"Joe Sandbox connector smoke test {message_id}"
    message["Message-ID"] = f"<{message_id}@example.invalid>"
    message["Date"] = datetime.now(timezone.utc)
    message.set_content("Harmless connector test. Plain text only, no links or active content.\n")
    message.add_attachment(attachment, maintype="text", subtype="plain", filename="test-note.txt")
    eml = message.as_bytes()
    (directory / "sample.eml").write_bytes(eml)
    write_json(directory / "input.json", {
        "message_id": message_id, "eml_bytes": len(eml),
        "eml_sha256": hashlib.sha256(eml).hexdigest(),
        "attachment_sha256": hashlib.sha256(attachment).hexdigest(),
    })


class PhisherSimulator:
    def __init__(self, directory, config):
        self.directory = directory
        self.eml = (directory / "sample.eml").read_bytes()
        self.input = json.loads((directory / "input.json").read_text())
        self.path = directory / "phisher.json"
        if self.path.exists():
            self.data = json.loads(self.path.read_text())
        else:
            self.data = {
                "message": {"id": self.input["message_id"], "pipelineStatus": "PROCESSED",
                            "actionStatus": "RECEIVED", "category": "UNKNOWN",
                            "tags": [{"name": config.ingestion_tag}] if config.ingestion_tag else [],
                            "comments": []},
                "operations": [], "downloads": 0,
            }

    def save(self):
        write_json(self.path, self.data)

    def handler(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            # Never log request URLs/headers or credentials through the default HTTP logger.
            def log_message(self, *_):
                pass

            def send_json(self, status, value):
                body = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path != "/sample.eml":
                    self.send_json(404, {"error": "unknown fixture"})
                    return
                if self.headers.get("Authorization"):
                    self.send_json(400, {"error": "API authorization must not reach EML downloads"})
                    return
                fixture.data["downloads"] += 1
                fixture.save()
                self.send_response(200)
                self.send_header("Content-Type", "message/rfc822")
                self.send_header("Content-Length", str(len(fixture.eml)))
                self.end_headers()
                self.wfile.write(fixture.eml)

            def do_POST(self):
                if self.path != "/graphql?scope=phisher":
                    self.send_json(404, {"error": "unexpected GraphQL route"})
                    return
                if self.headers.get("Authorization") != "Bearer local-smoke-test":
                    self.send_json(401, {"error": "invalid fixture token"})
                    return
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                query, values = request["query"], request["variables"]
                message = fixture.data["message"]
                operation = query.split("{", 1)[1].strip().split("(", 1)[0].split()[0]
                fixture.data["operations"].append(operation)
                if "query Discover" in query:
                    result = {"phisherMessages": {"nodes": [message], "pagination": {"pages": 1}}}
                elif "query Message" in query:
                    result = {"phisherMessage": message}
                elif values.get("id") != message["id"]:
                    self.send_json(400, {"error": "unexpected message ID"})
                    return
                elif "phisherTagsCreate" in query:
                    tags = {tag["name"] for tag in message["tags"]} | set(values["tags"])
                    message["tags"] = [{"name": tag} for tag in sorted(tags)]
                    result = {"phisherTagsCreate": {"errors": None, "nodes": message["tags"]}}
                elif "phisherTagsDelete" in query:
                    message["tags"] = [tag for tag in message["tags"] if tag["name"] not in values["tags"]]
                    result = {"phisherTagsDelete": {"errors": None, "nodes": message["tags"]}}
                elif "phisherCommentCreate" in query:
                    comment = {"body": values["comment"]}
                    message["comments"].append(comment)
                    result = {"phisherCommentCreate": {"errors": None, "node": comment}}
                elif "phisherMessageUpdate" in query:
                    message["category"] = "THREAT"
                    result = {"phisherMessageUpdate": {"errors": None, "node": {"id": message["id"]}}}
                else:
                    self.send_json(400, {"error": "unsupported fixture operation"})
                    return
                fixture.save()
                self.send_json(200, {"data": result})

        return Handler


class AuditedTransport(Transport):
    def __init__(self, config, directory):
        super().__init__(config.request_timeout, proxy_url=config.proxy_url)
        self.directory = directory

    def post(self, url, **kwargs):
        # Record only endpoint paths, never keys, form bodies, raw responses or proxy URLs.
        event = {"time": time.time(), "endpoint": url.split("/api/", 1)[-1],
                 "is_submission": bool(kwargs.get("submission")),
                 "requested_reverser": kwargs.get("data", {}).get("analyze-on-reverser") == "1"}
        with (self.directory / "joe-requests.jsonl").open("a") as handle:
            handle.write(json.dumps(event) + "\n")
        return super().post(url, **kwargs)


class OfflineJoe:
    # The offline mode tests the simulator itself without any Joe account or submission.
    def __init__(self, digest, verdict):
        self.digest = digest
        self.verdict = verdict
        self.submissions = 0

    def submit(self, eml, marker):
        assert hashlib.sha256(eml).hexdigest() == self.digest
        self.submissions += 1
        return "offline-submission"

    def submission(self, submission_id):
        return {"status": "finished", "analyses": [{"webid": "offline-analysis", "analysis_type": "sandbox"}]}

    def analysis(self, webid):
        score = {"clean": 0, "suspicious": 45, "malicious": 95}[self.verdict]
        return {"webid": webid, "status": "finished", "detection": self.verdict, "score": score,
                "sha256": self.digest, "threatname": "Simulated test verdict" if score else "",
                "runs": [{"detection": self.verdict, "error": "", "score": score}]}

    def report_link(self, webid, analysis_type=None):
        return "https://example.invalid/analysis/offline-analysis/0/html"


def submission_count(directory, joe):
    if isinstance(joe, OfflineJoe):
        return joe.submissions
    path = directory / "joe-requests.jsonl"
    return sum(json.loads(line)["is_submission"] for line in path.read_text().splitlines()) if path.exists() else 0


def run(args):
    config = Config.read(args.config)
    if args.live and args.offline_verdict != "clean":
        raise ValueError("--offline-verdict applies only to simulated Joe responses")
    if args.live and not config.joe_api_key:
        raise ValueError("A Joe Cloud API key is required for --live")
    directory = Path(args.output).resolve()
    if args.resume:
        if not (directory / "input.json").exists():
            raise ValueError("--resume requires an existing test output directory")
    else:
        directory.mkdir(parents=True, exist_ok=False)
        create_email(directory)
    fixture = PhisherSimulator(directory, config)
    config = replace(config, state_path=str(directory / "state.sqlite3"),
                     phisher_api_token="local-smoke-test", message_filter="")

    with tempfile.TemporaryDirectory(prefix="joe-phisher-tls-") as tls_directory:
        tls_path = Path(tls_directory)
        cert, key = tls_path / "cert.pem", tls_path / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server = ThreadingHTTPServer(("127.0.0.1", 0), fixture.handler())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"https://127.0.0.1:{server.server_port}"
        fixture.data["message"]["rawUrl"] = origin + "/sample.eml"
        fixture.save()
        local_transport = Transport(config.request_timeout)
        local_transport.session.verify = str(cert)
        phisher = Phisher(replace(config, phisher_endpoint=origin + "/graphql"),
                          "local-smoke-test", local_transport)
        joe = (JoeSandbox(config, config.joe_api_key, AuditedTransport(config, directory)) if args.live
               else OfflineJoe(fixture.input["eml_sha256"], args.offline_verdict))
        try:
            with instance_lock(config.state_path):
                state = State(config.state_path)
                try:
                    worker = Worker(config, state, phisher, joe)
                    deadline = time.monotonic() + args.max_seconds
                    previous = None
                    while time.monotonic() < deadline:
                        worker.tick()
                        job = state.get(fixture.input["message_id"])
                        summary = (job["phase"], job.get("submission_id")) if job else None
                        if summary != previous:
                            print(json.dumps({"phase": summary[0], "submission_id": summary[1]}) if summary else "Discovering", flush=True)
                            previous = summary
                        if job and job["phase"] in {"done", "error", "timeout", "blocked"}:
                            break
                        time.sleep(1)
                    else:
                        raise TimeoutError("Test deadline elapsed; use --resume with the same output directory")
                    if job["phase"] != "done":
                        raise RuntimeError("Test did not complete: " + job["phase"] + "; " + job.get("error", "unknown error"))

                    tags = {tag["name"] for tag in fixture.data["message"]["tags"]}
                    expected = {SUBMITTED, COMPLETED}
                    verdict_tag = {"malicious": MALICIOUS, "suspicious": SUSPICIOUS}.get(job["verdict"])
                    if verdict_tag:
                        expected.add(verdict_tag)
                    assert expected <= tags, "Expected result tags missing"
                    assert final_comment(job) in [item["body"] for item in fixture.data["message"]["comments"]]
                    if job["verdict"] == "malicious" and config.set_category_on_malicious:
                        assert fixture.data["message"]["category"] == "THREAT"
                    serialized = json.dumps(state.jobs())
                    assert "Harmless connector test" not in serialized and "/sample.eml" not in serialized
                    before_restart = submission_count(directory, joe)
                finally:
                    state.close()

                # Reopen durable state and exercise discovery again after completion.
                restarted = State(config.state_path)
                try:
                    Worker(config, restarted, phisher, joe).tick()
                    assert submission_count(directory, joe) == before_restart, "Restart resubmitted the email"
                finally:
                    restarted.close()
            report = {"mode": "live-joe/simulated-phisher" if args.live else "offline-joe/simulated-phisher",
                      "input": fixture.input, "submission_id": job["submission_id"],
                      "verdict": job["verdict"], "results": job["results"], "tags": sorted(tags),
                      "category": fixture.data["message"]["category"],
                      "eml_downloads": fixture.data["downloads"], "submission_attempts": before_restart,
                      "restart_did_not_resubmit": True, "eml_absent_from_database": True}
            known_hashes = {fixture.input["eml_sha256"], fixture.input["attachment_sha256"]}
            report["matching_input_hashes"] = [r["sha256"] for r in job["results"] if r["sha256"] in known_hashes]
            write_json(directory / "result.json", report)
            print(json.dumps(report, indent=2), flush=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--output", required=True)
    parser.add_argument("--live", action="store_true", help="Submit the harmless test EML to real Joe Cloud")
    parser.add_argument("--offline-verdict", choices=("clean", "suspicious", "malicious"), default="clean",
                        help="Simulated verdict for testing tag/category branches without malicious samples")
    parser.add_argument("--resume", action="store_true", help="Reuse test state; never creates a new test EML")
    parser.add_argument("--max-seconds", type=int, default=900)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run(args)


if __name__ == "__main__":
    main()
