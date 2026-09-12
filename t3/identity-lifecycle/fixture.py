"""Disposable Compose fixture and its in-volume preparation/HTTP helper.

ref: docker/compose pkg/compose/stop.go @ v5.5.1.
The candidate renderer remains the sole owner of the product topology.
"""
import base64
import copy
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import time
import uuid


def helper_prepare(data):
    root = Path(data["root"])
    inputs = root / "input"
    inputs.mkdir(mode=0o755)
    source = json.loads(Path("/candidate/deployment/example.json").read_text())
    def remap(value):
        if isinstance(value, dict):
            return {key: remap(item) for key, item in value.items()}
        if isinstance(value, list):
            return [remap(item) for item in value]
        if isinstance(value, str) and value.startswith("/srv/rss-identity/input/"):
            path = inputs / Path(value).name
            path.write_text(secrets.token_urlsafe(48))
            path.chmod(0o600)
            os.chown(path, 10001, 10001)
            return str(path)
        return value
    source = remap(source)
    runtime = source["runtime"]
    tenant = str(uuid.uuid4())
    principal = str(uuid.uuid4())
    runtime["identity_origin"] = {"environment_id": data["project"], "config_version": 1,
        "identity_public_origin": "https://identity.t31.test", "product_public_origin": "https://mdm.t31.test"}
    runtime["storage"] = {"target": list(secrets.token_bytes(16)), "lineage": list(secrets.token_bytes(16)),
                          "tenants": [{"tenant_id": tenant, "epoch": 1}]}
    back = ipaddress.ip_network(data["backend"])
    protocol = ipaddress.ip_network(data["protocol"])
    runtime["public_gateway"], runtime["private_gateway"] = str(back[2]), str(back[3])
    runtime["budgets"] = {"request_seconds": 20, "resource_seconds": 8, "drain_seconds": 25}
    provider = runtime["oidc"]["providers"][0]
    provider.update(tenant_id=tenant, issuer="https://sso.t31.test/realms/identity", addresses=[str(protocol[2]) + "/32"])
    runtime["hydra"]["addresses"] = [str(protocol[5]) + "/32"]
    runtime["hydra"]["clients"][0]["tenant_id"] = tenant
    source.update(backend_subnet=data["backend"], protocol_subnet=data["protocol"], consumer_network=data["consumer"])
    Path(runtime["oidc"]["state_key_file"]).write_text(secrets.token_hex(32))
    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=30)
    ca = inputs / "ca.pem"
    ca_key = inputs / "ca.key"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=identity-t31",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(ca_key), "-out", str(ca))
    ca_key.chmod(0o600)
    for label, names, owner in [("tls", "DNS:identity.t31.test,DNS:sso.t31.test", (10001, 10001)),
                               ("postgres", "DNS:postgres", (10001, 10001)),
                               ("hydra_admin", "DNS:hydra-admin", (10001, 10001)),
                               ("keycloak", "DNS:keycloak", (1000, 0))]:
        certificate = Path(source[label + "_certificate_file"])
        key = Path(source[label + "_key_file"])
        csr, extension = inputs / (label + ".csr"), inputs / (label + ".ext")
        extension.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=" + names + "\n")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + label,
                "-keyout", str(key), "-out", str(csr))
        openssl("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                "-CAcreateserial", "-days", "2", "-extfile", str(extension), "-out", str(certificate))
        openssl("verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", str(ca), str(certificate))
        key.chmod(0o600)
        os.chown(key, *owner)
        certificate.chmod(0o644)
    for path in [runtime["database"]["ca_file"], runtime["oidc"]["ca_file"], runtime["hydra"]["ca_file"]]:
        Path(path).write_bytes(ca.read_bytes())
        Path(path).chmod(0o644)
    password = inputs / "admin-password"
    password.write_text(secrets.token_urlsafe(48))
    password.chmod(0o600)
    os.chown(password, 10001, 10001)
    deployment = root / "deployment.json"
    deployment.write_text(json.dumps(source))
    deployment.chmod(0o600)
    subprocess.run([sys.executable, "/candidate/deploy.py", "--input", str(deployment),
                    "--output", str(root / "rendered"), "--candidate", "/candidate/candidate.json"],
                   check=True, capture_output=True, timeout=30)
    return {"tenant": tenant, "principal": principal, "public_ip": str(back[2]),
            "private_ip": str(back[3]), "backend_ip": str(back[4]), "protocol_gateway": str(protocol[2]),
            "deployment_sha256": hashlib.sha256(deployment.read_bytes()).hexdigest()}


def helper_http(data):
    class Connection(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection((data["address"], data.get("port", 443)), timeout=self.timeout)
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
    context = ssl.create_default_context(cafile=data["ca"])
    connection = Connection(data.get("host", "identity.t31.test"), context=context, timeout=data.get("timeout", 25))
    try:
        body = json.dumps(data["body"]) if "body" in data else None
        connection.request(data.get("method", "GET"), data["path"], body, data.get("headers", {}))
        response = connection.getresponse()
        content = response.read(65537)
        if len(content) > 65536:
            raise ValueError("response_too_large")
        try:
            value = json.loads(content)
        except (ValueError, UnicodeDecodeError):
            value = None
        return {"status": response.status, "json": value, "empty": not content,
                "headers": dict(response.getheaders())}
    finally:
        connection.close()


if __name__ == "__main__":
    operation = sys.argv[1]
    data = json.load(sys.stdin)
    value = helper_prepare(data) if operation == "prepare" else helper_http(data)
    print(json.dumps(value))
    sys.exit(0)


from run import Failure, HERE, ROOT, require, sha
sys.path.insert(0, str(ROOT / "hack"))
from bounded_process import run as bounded_run


def command(args, *, timeout=60, check=True, **kwargs):
    if "input" in kwargs:
        kwargs["stdin"] = subprocess.PIPE
    result = bounded_run(args, timeout=timeout, capture_output=True, text=True, **kwargs)
    if check and result.returncode:
        raise Failure("command_" + args[0].split("/")[-1] + "_" + str(result.returncode))
    return result


def eventually(probe, *, timeout=120, code="condition_timeout"):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        try:
            value = probe()
            if value:
                return value
        except (Failure, subprocess.TimeoutExpired):
            pass
        time.sleep(0.25)
    raise Failure(code)


class Fixture:
    def __init__(self, candidate_dir, candidate, output):
        self.candidate_dir, self.candidate, self.output = candidate_dir, candidate, output
        self.project = "identity-t31-" + uuid.uuid4().hex[:12]
        self.helper = self.project + "-helper"
        self.control = self.project + "-control"
        self.consumer = self.project + "-consumer"
        self.compose_file = output / "compose.json"
        self.info = {}
        self.cookie = None
        self.csrf = None

    def docker(self, *args, **kwargs):
        check = kwargs.pop("check", True)
        result = command(["docker", *args], check=False, **kwargs)
        if check and result.returncode:
            path = self.output / "diagnostics.private.log"
            with path.open("a") as log:
                path.chmod(0o600)
                log.write("operation=" + " ".join(args[:3]) + "\n" + result.stderr + "\n")
            raise Failure("docker_" + args[0] + "_failed")
        return result

    def compose(self, *args, **kwargs):
        return self.docker("compose", "-p", self.project, "-f", str(self.compose_file), *args, **kwargs)

    def helper_call(self, operation, data, **kwargs):
        result = self.docker("exec", "-i", self.helper, "python3", "/fixture.py", operation,
                             input=json.dumps(data), **kwargs)
        return json.loads(result.stdout)

    def helper_python(self, script, data=None, **kwargs):
        return self.docker("exec", "-i", self.helper, "python3", "-c", script,
                           input=json.dumps(data), **kwargs).stdout

    def prepare(self):
        engine = json.loads(self.docker("version", "--format", "{{json .Server}}").stdout)
        self.engine_arch = engine["Arch"]
        actual = {}
        for name, archive in self.candidate["archives"].items():
            self.docker("load", "--input", str(self.candidate_dir / archive["file"]), timeout=180)
            image = self.candidate["images"][name]
            info = json.loads(self.docker("image", "inspect", image).stdout)[0]
            require(info["Architecture"] == "amd64" and info["Os"] == "linux", "loaded_platform")
            require(info["Config"]["Labels"]["org.opencontainers.image.revision"] == self.candidate["revision"], "loaded_revision")
            actual[name] = {"id": info["Id"], "platform": info["Os"] + "/" + info["Architecture"]}
        for name, image in self.candidate["providers"].items():
            platform = "linux/" + self.engine_arch
            exists = self.docker("image", "inspect", "--platform", platform, image, check=False)
            present = json.loads(exists.stdout)[0] if exists.returncode == 0 else {}
            if present.get("Architecture") != platform.split("/")[1]:
                self.docker("pull", "--platform", platform, image, timeout=300)
            info = json.loads(self.docker("image", "inspect", "--platform", platform, image).stdout)[0]
            require(info["Architecture"] == platform.split("/")[1] and info["Os"] == "linux", "provider_platform")
            actual[name] = {"id": info["Id"], "platform": info["Os"] + "/" + info["Architecture"]}
        networks = self.docker("network", "ls", "--format", "{{.ID}}").stdout.split()
        allocated = []
        for network in networks:
            for config in json.loads(self.docker("network", "inspect", network).stdout)[0]["IPAM"].get("Config") or []:
                if config.get("Subnet"):
                    allocated.append(ipaddress.ip_network(config["Subnet"]))
        available = [f"10.234.{i}.0/24" for i in range(1, 255)
                     if not any(ipaddress.ip_network(f"10.234.{i}.0/24").overlaps(v) for v in allocated if v.version == 4)]
        require(len(available) >= 2, "no_fixture_networks")
        selected = secrets.SystemRandom().sample(available, 2)
        self.docker("volume", "create", "--label", "rss.t31=" + self.project, self.control)
        self.mount = self.docker("volume", "inspect", "--format", "{{.Mountpoint}}", self.control).stdout.strip()
        self.docker("network", "create", "--internal", "--label", "rss.t31=" + self.project, self.consumer)
        self.docker("run", "--detach", "--pull", "never", "--name", self.helper, "--label", "rss.t31=" + self.project,
                    "--network", self.consumer, "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=64m",
                    "--mount", f"type=volume,source={self.control},target={self.mount}",
                    "--mount", f"type=bind,source={self.candidate_dir},target=/candidate,readonly",
                    "--mount", f"type=bind,source={HERE / 'fixture.py'},target=/fixture.py,readonly",
                    self.candidate["providers"]["rust"], "python3", "-c", "import time; time.sleep(86400)")
        self.info = self.helper_call("prepare", {"root": self.mount, "project": self.project,
            "backend": selected[0], "protocol": selected[1], "consumer": self.consumer}, timeout=120)
        # Test the daemon-native file mount with the actual runtime ownership before starting any product.
        self.docker("run", "--rm", "--pull", "never", "--network", "none", "--user", "10001:10001",
                    "--mount", f"type=bind,source={self.mount}/rendered/runtime.json,target=/check,readonly",
                    self.candidate["providers"]["rust"], "sh", "-ec",
                    'test "$(stat -c %u:%g:%a /check)" = 10001:10001:600; test -r /check')
        self.docker("cp", self.helper + ":" + self.mount + "/rendered/compose.json", str(self.compose_file))
        self.public_ca = self.output / "public-ca.pem"
        self.docker("cp", self.helper + ":" + self.mount + "/input/ca.pem", str(self.public_ca))
        value = json.loads(self.compose_file.read_text())
        value["name"] = self.project
        for service in value["services"].values():
            service["platform"] = "linux/amd64" if service["image"] in self.candidate["images"].values() else "linux/" + self.engine_arch
            service["pull_policy"] = "never"
        value["services"]["public-gateway"]["ports"] = [{"target": 443, "host_ip": "127.0.0.1", "protocol": "tcp"}]
        self.compose_file.write_text(json.dumps(value, indent=2))
        self.compose_file.chmod(0o600)
        self.config = value
        return {"docker": engine["Version"], "compose": self.docker("compose", "version", "--short").stdout.strip(),
                "engine_platform": "linux/" + self.engine_arch, "product_platform": "linux/amd64",
                "emulated": self.engine_arch != "amd64", "images": actual,
                "deployment_sha256": self.info["deployment_sha256"], "compose_sha256": sha(self.compose_file),
                "daemon_native_bind": True}

    def connect_helper(self):
        self.docker("network", "connect", self.project + "_backend", self.helper)

    def cid(self, service):
        value = self.compose("ps", "--all", "--quiet", service).stdout.strip()
        require(bool(value) and "\n" not in value, "missing_service")
        return value

    def state(self, service):
        state = json.loads(self.docker("inspect", self.cid(service)).stdout)[0]
        return {"status": state["State"]["Status"], "exit_code": state["State"]["ExitCode"],
                "oom": state["State"]["OOMKilled"], "started": state["State"]["StartedAt"],
                "finished": state["State"]["FinishedAt"], "restarts": state["RestartCount"],
                "image": state["Image"]}

    def sql(self, statement, *, check=True):
        return self.compose("exec", "-T", "postgres", "psql", "-X", "-A", "-t", "-U", "postgres",
                            "-d", "identity", "-v", "ON_ERROR_STOP=1", input=statement, check=check).stdout.strip()

    def probe(self):
        return self.compose("exec", "-T", "identity", "identity-server", "--probe", "127.0.0.1:8080",
                            check=False, timeout=20).returncode == 0

    def ready(self):
        eventually(self.probe, timeout=180, code="identity_not_ready")

    def up(self, *services):
        self.compose("up", "-d", "--pull", "never", *services, timeout=300)

    def http(self, path, *, method="GET", body=None, private=False, session=False, host=None, timeout=25):
        headers = {"Origin": "https://identity.t31.test", "X-Identity-Request": "1", "Content-Type": "application/json"}
        if session:
            headers.update(Cookie=self.cookie, **{"X-CSRF-Token": self.csrf})
        if private:
            raw = self.helper_python("import json,pathlib,sys; d=json.load(sys.stdin); print(pathlib.Path(d).read_text())",
                                     self.mount + "/input/mdm-validation-secret").strip()
            headers["Authorization"] = "Basic " + base64.b64encode(("mdm:" + raw).encode()).decode()
        data = {"ca": self.mount + "/input/ca.pem", "address": self.info["private_ip" if private else "public_ip"],
                "port": 443, "host": host or "identity.t31.test", "path": path,
                "method": method, "headers": headers, "timeout": timeout}
        if body is not None:
            data["body"] = body
        return self.helper_call("http", data, timeout=timeout + 5)

    def published(self):
        mapping = self.compose("port", "public-gateway", "443").stdout.strip()
        require(mapping.startswith("127.0.0.1:"), "public_port_not_loopback")
        try:
            return helper_http({"ca": str(self.public_ca), "address": "127.0.0.1",
                                "port": int(mapping.rsplit(":", 1)[1]), "path": "/identity-build.json"})
        except (OSError, http.client.HTTPException):
            raise Failure("published_endpoint_unavailable") from None

    def login(self):
        password = self.helper_python("import json,pathlib,sys; print(pathlib.Path(json.load(sys.stdin)).read_text())",
                                      self.mount + "/input/admin-password").strip()
        response = self.http("/api/v1/tenants/" + self.info["tenant"] + "/login", method="POST",
                             body={"login": "t31-admin", "password": password})
        require(response["status"] == 200, "local_login")
        self.cookie = next(value for key, value in response["headers"].items() if key.lower() == "set-cookie").split(";", 1)[0]
        self.csrf = response["json"]["csrf_token"]

    def diagnostics(self):
        result = {}
        if self.compose_file.exists():
            for service in ("postgres", "hydra", "hydra-admin", "keycloak", "identity", "public-gateway"):
                try:
                    result[service] = self.state(service)
                except Exception:
                    result[service] = {"status": "unavailable"}
        return result

    def cleanup(self):
        # Engine ownership labels work even when Compose rejected the rendered file.
        ok = True
        owned = []
        for kind, listing in (("container", ("ps", "--all")), ("network", ("network", "ls")), ("volume", ("volume", "ls"))):
            try:
                for label in ("com.docker.compose.project=", "rss.t31="):
                    ids = self.docker(*listing, "--filter", "label=" + label + self.project,
                                      "--format", "{{.ID}}" if kind != "volume" else "{{.Name}}").stdout.split()
                    owned.extend((kind, name) for name in ids)
            except Exception:
                ok = False
        resources = sorted(owned, key=lambda item: {"container": 0, "network": 1, "volume": 2}[item[0]])
        for kind, name in dict.fromkeys(resources):
            try:
                if kind == "container":
                    if name != self.helper:
                        self.docker("stop", "--timeout", "40", name, timeout=50)
                    self.docker("rm", "--force", name)
                else:
                    self.docker(kind, "rm", name)
            except Exception:
                ok = False
        return ok
