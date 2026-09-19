import copy
import json
import unittest
from unittest.mock import patch
import reference_approval as approval


class ApprovalTests(unittest.TestCase):
    def fixture(self):
        targets = {
            "subject": {"pullRequest": 1062, "runnerRevision": "a" * 40},
            "baselineSha256": "b" * 64,
            "limits": {"errors": 0},
            "approvalReference": "https://dev.azure.com/shengming0923/rss/_git/rss-identity/pullrequest/1062?discussionId=123",
        }
        body = {
            "approved": True,
            **{key: targets[key] for key in ["subject", "baselineSha256", "limits"]},
            "humanApproval": {"requestId": "human-request-123", "source": "feishu"},
        }
        pr = {
            "pullRequestId": 1062,
            "repository": {
                "id": approval.REPOSITORY,
                "project": {"id": approval.PROJECT},
            },
            "createdBy": {"id": "owner-id"},
            "lastMergeSourceCommit": {"commitId": "a" * 40},
        }
        comment = {
            "id": 1,
            "author": {"id": "owner-id"},
            "commentType": "text",
            "content": approval.MARKER + "\n```json\n" + json.dumps(body) + "\n```",
        }
        return targets, pr, {"id": 123, "comments": [comment]}, body

    def test_owner_comment_must_approve_exact_candidate_baseline_and_limits(self):
        targets, pr, thread, body = self.fixture()
        with patch.object(approval, "get_json", side_effect=[pr, thread]):
            receipt = approval.verify_approval(targets, 1062)
        self.assertEqual(receipt["authorId"], "owner-id")
        self.assertEqual(receipt["humanApproval"], body["humanApproval"])
        mutations = [
            lambda p, t: p.update(pullRequestId=1057),
            lambda p, t: p["repository"].update(id="other-repo"),
            lambda p, t: p["lastMergeSourceCommit"].update(commitId="c" * 40),
            lambda p, t: t.update(id=124),
            lambda p, t: t.update(isDeleted=True),
            lambda p, t: t["comments"][0].update(isDeleted=True),
            lambda p, t: t["comments"][0]["author"].update(id="another-user"),
            lambda p, t: t["comments"][0].update(
                content=t["comments"][0]["content"].replace(
                    '"approved": true', '"approved": false'
                )
            ),
            lambda p, t: t["comments"][0].update(
                content=t["comments"][0]["content"].replace(
                    '"errors": 0', '"errors": 1'
                )
            ),
            lambda p, t: t["comments"][0].update(
                content=t["comments"][0]["content"].replace(
                    '"errors": 0', '"errors": false'
                )
            ),
            lambda p, t: t["comments"][0].update(
                content=t["comments"][0]["content"].replace(
                    '"approved": true', '"approved": false, "approved": true'
                )
            ),
        ]
        for mutate in mutations:
            altered_pr, altered_thread = copy.deepcopy(pr), copy.deepcopy(thread)
            mutate(altered_pr, altered_thread)
            with self.subTest(mutate=mutate), patch.object(
                approval, "get_json", side_effect=[altered_pr, altered_thread]
            ):
                with self.assertRaisesRegex(ValueError, "approval"):
                    approval.verify_approval(targets, 1062)

    def test_invalid_reference_is_rejected_before_authentication(self):
        targets, _, _, _ = self.fixture()
        for url in [
            targets["approvalReference"].replace("1062?", "1057?"),
            targets["approvalReference"] + "&token=secret",
            "https://evil.test/123",
        ]:
            with patch.object(approval, "get_json") as get:
                with self.assertRaises(ValueError):
                    approval.verify_approval(
                        {**targets, "approvalReference": url}, 1062
                    )
                get.assert_not_called()

    def test_transport_fails_closed_without_exposing_credentials(self):
        with patch.object(
            approval, "authorization", return_value="Bearer secret"
        ), patch.object(approval, "build_opener", side_effect=OSError("secret")):
            with self.assertRaisesRegex(ValueError, "^approval-unavailable$"):
                approval.get_json("pullRequests/1062")

    def test_redirects_never_forward_authorization(self):
        with self.assertRaises(ValueError):
            approval.NoRedirect().redirect_request(
                None, None, 302, "found", {}, "https://evil.test"
            )
