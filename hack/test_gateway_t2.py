import os
import subprocess
import sys
import unittest
from unittest.mock import patch

import gateway_t2


class GatewayTests(unittest.TestCase):
    def test_network_collision_retries_before_starting_fixture(self):
        attempted = []

        def docker(*args):
            if args[:2] == ("network", "ls"):
                return ""
            self.assertEqual(args[:2], ("network", "create"))
            attempted.append(args[args.index("--subnet") + 1])
            if len(attempted) == 1:
                raise subprocess.CalledProcessError(
                    1,
                    ["docker", *args],
                    stderr="Error response from daemon: invalid pool request: Pool overlaps with other one on this address space\n",
                )
            return "network-id"

        with (
            patch.object(gateway_t2, "docker", side_effect=docker),
            patch.object(
                gateway_t2, "fixture", side_effect=RuntimeError("fixture-started")
            ),
            patch.object(
                gateway_t2.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "fixture-started"):
                gateway_t2.gateway()
        self.assertEqual(attempted, ["10.242.0.0/24", "10.242.1.0/24"])

    def test_runner_import_does_not_load_unit_tests(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import gateway_t2, sys; "
                "assert not any(name.startswith('test_') for name in sys.modules)",
            ],
            env={**os.environ, "PYTHONPATH": str(gateway_t2.deploy.ROOT / "hack")},
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

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
                side_effect=subprocess.TimeoutExpired("docker", 1),
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
