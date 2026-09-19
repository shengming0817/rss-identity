import subprocess
import unittest
from unittest.mock import Mock
from docker_network import create_network


class NetworkTests(unittest.TestCase):
    def test_only_known_overlap_retries_and_preserves_owner(self):
        overlap = subprocess.CalledProcessError(
            1,
            "docker",
            stderr=b"Error response from daemon: invalid pool request: Pool overlaps with other one on this address space\n",
        )
        docker = Mock(side_effect=[overlap, b"id"])
        self.assertEqual(
            create_network(
                docker,
                "owned",
                ["10.243.0.0/24", "10.243.1.0/24"],
                labels=["owner=fixture"],
                internal=True,
            ),
            "10.243.1.0/24",
        )
        for call in docker.call_args_list:
            self.assertEqual(call.args[-1], "owned")
            self.assertIn("owner=fixture", call.args)
            self.assertIn("--internal", call.args)

    def test_unknown_failure_is_not_retried_and_is_redacted(self):
        docker = Mock(
            side_effect=subprocess.CalledProcessError(1, "docker", stderr=b"secret")
        )
        with self.assertRaisesRegex(RuntimeError, "^network-create-failed$"):
            create_network(docker, "owned", ["a", "b"])
        self.assertEqual(docker.call_count, 1)

    def test_timeout_is_not_retried(self):
        docker = Mock(side_effect=subprocess.TimeoutExpired("docker", 1))
        with self.assertRaises(subprocess.TimeoutExpired):
            create_network(docker, "owned", ["a", "b"])
        self.assertEqual(docker.call_count, 1)
