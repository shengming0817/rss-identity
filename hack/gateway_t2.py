#!/usr/bin/env python3
"""Real Nginx transport T2; no Identity product/capacity acceptance here."""

import contextlib
import http.client
import ipaddress
import json
import os
import ssl
import subprocess
import sys
import time
import uuid
from unittest.mock import patch

import deploy
from providers import IMAGES, container, docker, wait
from test_deployment import fixture


def verify_rows(rows, source):
    deploy.require(len(rows) == 64, "gateway sample count")
    for i, row in enumerate(rows):
        deploy.require(
            row["source"] == source and row["host"] == "identity.example.test",
            "gateway source/host",
        )
        deploy.require(row["cookie"] == f"probe={i}", "gateway cookie isolation")
        ipaddress.ip_address(row["xff"])
        deploy.require(
            all(
                row[k] == ""
                for k in ["forwarded", "real", "xfh", "xfp", "connectionHeader"]
            ),
            "gateway header isolation",
        )
    count = len({r["connection"] for r in rows})
    deploy.require(
        count == 1, f"gateway opened {count} upstream connections for 64 requests"
    )
    deploy.require(
        [int(r["requests"]) for r in rows] == list(range(1, 65)),
        "gateway connection request sequence",
    )


def gateway():
    # Select an unused private /24 without relying on daemon allocation order.
    names = docker("network", "ls", "-q").splitlines()
    networks = json.loads(docker("network", "inspect", *names)) if names else []
    used = [
        ipaddress.ip_network(item["Subnet"])
        for network in networks
        for item in network.get("IPAM", {}).get("Config") or []
        if item.get("Subnet")
    ]
    subnet = next(
        n
        for n in (ipaddress.ip_network(f"10.242.{i}.0/24") for i in range(256))
        if not any(n.overlaps(u) for u in used)
    )
    name = "identity-gateway-t2-" + uuid.uuid4().hex
    try:
        docker("network", "create", "--subnet", str(subnet), name)
        with fixture() as (root, data, images), contextlib.ExitStack() as stack:
            source, backend = str(subnet[2]), str(subnet[3])
            data["backendSubnet"] = str(subnet)
            data["runtime"]["publicGateway"] = source
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=identity.example.test",
                    "-addext",
                    "subjectAltName=IP:127.0.0.1",
                    "-keyout",
                    str(root / "key"),
                    "-out",
                    str(root / "cert"),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            with (
                patch("os.geteuid", return_value=0),
                patch("os.chown"),
                patch.object(deploy, "preflight"),
            ):
                deploy.render(data, root / "gateway", images)
            probe = root / "probe.conf"
            probe.write_text("""pid /tmp/nginx.pid;
error_log stderr crit;
events {}
http {
 access_log off;
 client_body_temp_path /tmp/client; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi;
 server { listen 8080;
  location / { default_type application/json;
   return 200 '{"connection":"$connection","requests":"$connection_requests","source":"$remote_addr","xff":"$http_x_forwarded_for","host":"$http_host","cookie":"$http_cookie","forwarded":"$http_forwarded","real":"$http_x_real_ip","xfh":"$http_x_forwarded_host","xfp":"$http_x_forwarded_proto","connectionHeader":"$http_connection"}';
  }
 }
}
""")
            user = f"{os.getuid()}:{os.getgid()}"
            args = [
                "nginx",
                "-c",
                "/etc/nginx/nginx.conf",
                "-e",
                "stderr",
                "-g",
                "daemon off;",
            ]
            _, backend_ports = stack.enter_context(
                container(
                    IMAGES["nginx"],
                    [8080],
                    args=args,
                    user=user,
                    network=name,
                    address=backend,
                    mounts=[f"{probe}:/etc/nginx/nginx.conf:ro"],
                )
            )
            wait(f"http://127.0.0.1:{backend_ports[8080]}/ready")
            _, ports = stack.enter_context(
                container(
                    IMAGES["nginx"],
                    [8443],
                    args=args,
                    user=user,
                    network=name,
                    address=source,
                    mounts=[
                        f"{root / 'gateway' / 'gateway.conf'}:/etc/nginx/nginx.conf:ro",
                        f"{root / 'gateway'}:/run/config:ro",
                        f"{root / 'gateway' / 'input'}:/run/input:ro",
                    ],
                )
            )
            context = ssl.create_default_context(cafile=str(root / "cert"))
            client = http.client.HTTPSConnection(
                "127.0.0.1", ports[8443], context=context, timeout=5
            )
            stack.callback(client.close)
            deadline = time.monotonic() + 20
            while True:
                try:
                    client.connect()
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)
            rows = []
            paths = [
                "/api/v2/probe",
                "/api/identity-host/v1/tenants/00000000-0000-0000-0000-000000000001/mfa-example",
            ]
            for i in range(64):
                client.request(
                    "GET",
                    paths[i % 2],
                    headers={
                        "Host": "identity.example.test",
                        "Cookie": f"probe={i}",
                        "X-Forwarded-For": "spoof",
                        "Forwarded": "spoof",
                        "X-Real-IP": "spoof",
                        "X-Forwarded-Host": "spoof",
                        "X-Forwarded-Proto": "spoof",
                        "Connection": "close",
                    },
                )
                response = client.getresponse()
                body = response.read()
                deploy.require(
                    response.status == 200, f"gateway returned HTTP {response.status}"
                )
                rows.append(json.loads(body))
            verify_rows(rows, source)
            print(
                "gateway T2: 64 requests across both routes reuse one upstream connection; headers isolated"
            )
    finally:
        failed = sys.exception() is not None
        try:
            removed = subprocess.run(
                ["docker", "network", "rm", name], capture_output=True, timeout=30
            )
            if removed.returncode:
                remaining = docker(
                    "network",
                    "ls",
                    "--filter",
                    f"name=^{name}$",
                    "--format",
                    "{{.Name}}",
                )
                deploy.require(not remaining, "gateway network cleanup failed")
        except (OSError, subprocess.SubprocessError, ValueError):
            if not failed:
                raise
            print("gateway network cleanup also failed", file=sys.stderr)


if __name__ == "__main__":
    gateway()
