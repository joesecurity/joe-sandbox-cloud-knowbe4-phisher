"""Plain-text discussion comments: legible without Markdown support."""

from urllib.parse import quote

def marker(job, stage):
    # The client looks for this stable reference before retrying a comment write.
    return f"[KnowBe4-PhishER:{job['job_id']}:{stage}]"


def final_comment(job, report_base_url="https://jbxcloud.joesecurity.org"):
    # Failure details stay in local state/logs; no failure comment is generated.
    if job["outcome"] != "done":
        raise ValueError("Discussion comments require a completed analysis result")
    results = job["results"]
    names = {}
    scores = []
    for result in results:
        name = result.get("threatname")
        if isinstance(name, str):
            name = " ".join(name.split())
            if name and name.casefold() not in {"unknown", "none", "n/a", "-"}:
                names.setdefault(name.casefold(), name)
        score = result.get("score")
        if type(score) in {int, float} and 0 <= score <= 100:
            scores.append(score)
    # The submission page groups all sandbox and Reverser analyses in one place.
    submission_id = quote(str(job["submission_id"]), safe="")
    link = f"{report_base_url.rstrip('/')}/submission/{submission_id}"
    lines = [f"Joe Sandbox Cloud Verdict: {job['verdict'].title()}"]
    lines.append("Threat name: " + (", ".join(names.values()) or "Not reported"))
    lines.extend([
        "Score: " + (f"{max(scores):g}/100" if scores else "Not reported"),
        f"Report: {link}",
    ])
    return "\n".join(lines)
