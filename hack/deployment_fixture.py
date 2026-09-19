"""Disposable deployment inputs shared by transport checks and tooling tests."""

import contextlib
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
import deploy


@contextlib.contextmanager
def fixture():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        value = json.loads((deploy.ROOT / "deployment/example.json").read_text())
        for name in [
            "runtime",
            "owner",
            "maintenance",
            "ca",
            "cert",
            "key",
            "pgcert",
            "pgkey",
        ]:
            p = root / name
            p.write_text("fixture-" + name)
            p.chmod(0o600)
        value["database"].update(
            passwordFile=str(root / "runtime"), caFile=str(root / "ca")
        )
        data = {
            "runtime": value,
            "ownerPasswordFile": str(root / "owner"),
            "maintenancePasswordFile": str(root / "maintenance"),
            "tlsCertificateFile": str(root / "cert"),
            "tlsKeyFile": str(root / "key"),
            "postgresCertificateFile": str(root / "pgcert"),
            "postgresKeyFile": str(root / "pgkey"),
            "backendSubnet": "172.29.0.0/24",
        }
        images = {
            k: "sha256:" + str(i) * 64
            for i, k in enumerate(["identity", "web", "postgres", "runtime"], 1)
        }
        with patch("os.geteuid", return_value=0), patch("os.chown"), patch.object(
            deploy, "preflight"
        ):
            deploy.render(data, root / "output", images)
        yield root, data, images
