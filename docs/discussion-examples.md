# Discussion comment examples

The connector posts only the final completed result. Pending states and failures
use tags. These examples use illustrative data.

With a reported threat name:

    Joe Sandbox Cloud Verdict: Malicious
    Threat name: Emotet
    Score: 95/100
    Report: https://jbxcloud.joesecurity.org/submission/6133578

Without a reported threat name:

    Joe Sandbox Cloud Verdict: Suspicious
    Threat name: Not reported
    Score: 45/100
    Report: https://jbxcloud.joesecurity.org/submission/6133578

Score is the highest score across sandbox and Joe Reverser results. The single
report link points to the submission page. Unknown results are not treated
as Clean. Threat name is shown as Not reported when no meaningful name is available.
