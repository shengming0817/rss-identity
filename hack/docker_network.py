"""Reserve fixture subnets at the Docker daemon's atomic network-create boundary."""

import subprocess


def create_network(docker, name, candidates, *, labels=(), internal=False):
    # Moby defaultipam returns this error before creating a conflicting network.
    overlap = "Error response from daemon: invalid pool request: Pool overlaps with other one on this address space"
    for subnet in candidates:
        command = ["network", "create", "--subnet", str(subnet)]
        if internal:
            command.append("--internal")
        for label in labels:
            command.extend(["--label", label])
        try:
            docker(*command, name)
            return str(subnet)
        except subprocess.CalledProcessError as error:
            raw = error.stderr or b""
            message = raw.decode(errors="replace") if isinstance(raw, bytes) else raw
            if message.strip() != overlap:
                raise RuntimeError("network-create-failed") from None
    raise RuntimeError("network-subnets-exhausted")
