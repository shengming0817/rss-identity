"""Read back owner approval from this repository's authenticated Azure API.

The owner is the PR creator, obtained from Azure, never from target input.
humanApproval identifies the operator's recorded human decision; Azure authenticates
its publisher and content, not the original Feishu/Codex interaction.
"""

import base64
import hashlib
import json
import os
import re
from urllib.request import HTTPRedirectHandler, Request, build_opener
from bounded_process import run as bounded_run

REPOSITORY = "e1257122-3ec2-4a42-a134-67e73e574e61"
PROJECT = "e9379e8d-e99e-40d2-a224-87b58eff9c3f"
BASE = f"https://dev.azure.com/shengming0923/{PROJECT}/_apis/git/repositories/{REPOSITORY}/"
MARKER = "rss-identity-reference-approval/v1"


def require(condition):
    if not condition:
        raise ValueError("approval-invalid")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("approval-invalid")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("approval-unavailable")


def authorization():
    pat = os.environ.get("AZURE_DEVOPS_EXT_PAT")
    if pat:
        return "Basic " + base64.b64encode((":" + pat).encode()).decode()
    token = (
        bounded_run(
            [
                "az",
                "account",
                "get-access-token",
                "--resource",
                "499b84ac-1321-427f-aa17-267ca6975798",
                "--query",
                "accessToken",
                "-o",
                "tsv",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        .stdout.decode()
        .strip()
    )
    require(bool(token))
    return "Bearer " + token


def get_json(path):
    try:
        request = Request(
            BASE + path + "?api-version=7.1",
            headers={"Authorization": authorization(), "Accept": "application/json"},
        )
        with build_opener(NoRedirect()).open(request, timeout=30) as response:
            raw = response.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024)
        return strict_json(raw)
    except Exception:
        raise ValueError("approval-unavailable") from None


def verify_approval(targets, pull_request):
    require(type(pull_request) is int and pull_request > 0)
    reference = targets.get("approvalReference")
    require(isinstance(reference, str))
    match = re.fullmatch(
        rf"https://dev\.azure\.com/shengming0923/rss/_git/rss-identity/pullrequest/{pull_request}\?discussionId=([1-9][0-9]*)",
        reference,
    )
    require(match is not None)
    thread_id = int(match[1])
    pr = get_json(f"pullRequests/{pull_request}")
    require(pr.get("pullRequestId") == pull_request)
    repository = pr.get("repository", {})
    require(
        repository.get("id") == REPOSITORY
        and repository.get("project", {}).get("id") == PROJECT
    )
    owner = pr.get("createdBy", {}).get("id")
    require(isinstance(owner, str) and bool(owner))
    require(
        pr.get("lastMergeSourceCommit", {}).get("commitId")
        == targets["subject"]["runnerRevision"]
    )
    require(targets["subject"].get("pullRequest") == pull_request)
    thread = get_json(f"pullRequests/{pull_request}/threads/{thread_id}")
    require(thread.get("id") == thread_id and not thread.get("isDeleted"))
    receipts = []
    for comment in thread.get("comments", []):
        if (
            comment.get("isDeleted")
            or comment.get("commentType") != "text"
            or comment.get("author", {}).get("id") != owner
        ):
            continue
        content = comment.get("content", "")
        match = re.fullmatch(
            re.escape(MARKER) + r"\n```json\n(.*)\n```\s*", content, re.DOTALL
        )
        if not match:
            continue
        try:
            payload = strict_json(match[1])
            require(
                set(payload)
                == {"approved", "subject", "baselineSha256", "limits", "humanApproval"}
                and payload["approved"] is True
            )
            require(
                all(
                    canonical(payload[key]) == canonical(targets[key])
                    for key in ["subject", "baselineSha256", "limits"]
                )
            )
            human = payload["humanApproval"]
            require(isinstance(human, dict) and set(human) == {"requestId", "source"})
            require(
                human["source"] in ["feishu", "codex", "dingTalk"]
                and isinstance(human["requestId"], str)
                and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", human["requestId"])
            )
            require(type(comment.get("id")) is int and comment["id"] > 0)
        except (ValueError, TypeError, KeyError):
            continue
        receipts.append(
            {
                "pullRequest": pull_request,
                "threadId": thread_id,
                "commentId": comment["id"],
                "authorId": owner,
                "contentSha256": hashlib.sha256(content.encode()).hexdigest(),
                "humanApproval": human,
            }
        )
    require(len(receipts) == 1)
    return receipts[0]


def validate_receipt(receipt, targets):
    require(
        isinstance(receipt, dict)
        and set(receipt)
        == {
            "pullRequest",
            "threadId",
            "commentId",
            "authorId",
            "contentSha256",
            "humanApproval",
        }
    )
    require(receipt["pullRequest"] == targets["subject"]["pullRequest"])
    require(
        all(
            type(receipt[key]) is int and receipt[key] > 0
            for key in ["pullRequest", "threadId", "commentId"]
        )
    )
    require(
        targets["approvalReference"].endswith(
            "?discussionId=" + str(receipt["threadId"])
        )
    )
    require(isinstance(receipt["authorId"], str) and bool(receipt["authorId"]))
    require(
        isinstance(receipt["contentSha256"], str)
        and re.fullmatch("[0-9a-f]{64}", receipt["contentSha256"])
    )
    human = receipt["humanApproval"]
    require(isinstance(human, dict) and set(human) == {"requestId", "source"})
    require(
        human["source"] in ["feishu", "codex", "dingTalk"]
        and isinstance(human["requestId"], str)
        and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", human["requestId"])
    )
