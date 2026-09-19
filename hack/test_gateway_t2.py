import os
import subprocess
import sys
import unittest
from unittest.mock import patch

import gateway_t2


class GatewayTests(unittest.TestCase):
    def test_optimized_python_still_rejects_missing_observations(self):
        result = subprocess.run(
            [
                sys.executable,
                "-O",
                "-c",
                'import gateway_t2; gateway_t2.verify_rows([], "10.242.0.2")',
            ],
            env={**os.environ, "PYTHONPATH": str(gateway_t2.deploy.ROOT / "hack")},
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("gateway sample count", result.stderr)

    def test_uncertain_network_creation_still_cleans_owned_name(self):
        with (
            patch.object(
                gateway_t2,
                "docker",
                side_effect=["", subprocess.TimeoutExpired("docker", 1)],
            ) as docker,
            patch.object(
                gateway_t2.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0),
            ) as remove,
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                gateway_t2.gateway()
        created = docker.call_args.args[-1]
        self.assertEqual(remove.call_args.args[0], ["docker", "network", "rm", created])
