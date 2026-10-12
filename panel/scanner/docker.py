"""
SentinelScan — scanner/docker.py
Docker & Container Security Audit
Phase 6 — Scan Modules Tier 3

Checks Docker daemon configuration, running container security posture,
image vulnerability indicators, network exposure, and Kubernetes
security configuration (if detected).
"""
from __future__ import annotations
import json
import os
import shutil
from typing import Iterator

from .base import ScanModule, Finding, Severity
from .orchestrator import register_module


@register_module
class DockerSecurityModule(ScanModule):
    name             = "docker_security"
    display_name     = "Docker / Container Security"
    category         = "Containers"
    description      = "Docker daemon config, container security posture, exposed socket, image hygiene"
    applies_to_os    = ["linux", "windows", "macos"]
    applies_to_mode  = ["workstation", "server"]

    def run(self) -> Iterator[Finding]:
        self._emit_progress(5, "Checking for container runtimes...")

        docker_present = shutil.which("docker") or os.path.exists("/var/run/docker.sock")
        podman_present = shutil.which("podman")
        k8s_present    = shutil.which("kubectl") or os.path.exists("/etc/kubernetes")

        if not docker_present and not podman_present and not k8s_present:
            yield Finding(
                title              = "No container runtime detected",
                severity           = Severity.INFO,
                category           = "Containers",
                description        = "Docker, Podman, and Kubernetes were not detected on this system.",
                affected_component = "Container runtime",
                remediation        = "No action required if containers are not used.",
            )
            return

        if docker_present:
            yield from self._check_docker()

        if podman_present:
            yield from self._check_podman()

        if k8s_present:
            yield from self._check_kubernetes()

    # ─────────────────────────────────────────────────────────────────────────
    # DOCKER
    # ─────────────────────────────────────────────────────────────────────────
    def _check_docker(self) -> Iterator[Finding]:
        self._emit_progress(10, "Auditing Docker daemon...")
        yield from self._check_docker_socket()
        yield from self._check_docker_daemon_config()
        yield from self._check_running_containers()
        yield from self._check_docker_images()
        yield from self._check_docker_networks()
        yield from self._check_docker_volumes()

    def _check_docker_socket(self) -> Iterator[Finding]:
        socket_path = "/var/run/docker.sock"
        if not os.path.exists(socket_path):
            return

        self._emit_progress(15, "Checking Docker socket permissions...")
        mode = oct(os.stat(socket_path).st_mode)[-3:]
        import stat as stat_mod
        full_mode = os.stat(socket_path).st_mode

        # Check if socket is world-writable
        if full_mode & stat_mod.S_IWOTH:
            yield Finding(
                title              = "Docker socket is world-writable!",
                severity           = Severity.CRITICAL,
                category           = "Containers",
                description        = f"/var/run/docker.sock (mode {mode}) is writable by all users. Any user can control the Docker daemon, mount host filesystem, and achieve full root access.",
                affected_component = "/var/run/docker.sock",
                remediation        = "Fix immediately:\nchmod 660 /var/run/docker.sock\nchown root:docker /var/run/docker.sock",
                cvss_score         = 10.0,
            )

        # Check docker group membership
        docker_group, _, _ = self.run_command(["getent", "group", "docker"], timeout=5)
        if docker_group:
            members = docker_group.strip().split(":")[-1].split(",")
            members = [m for m in members if m.strip()]
            if members:
                yield Finding(
                    title              = f"Docker group members (effectively root): {', '.join(members)}",
                    severity           = Severity.HIGH,
                    category           = "Containers",
                    description        = f"Members of the 'docker' group have root-equivalent access via the Docker socket: {', '.join(members)}. The Docker socket provides unrestricted host access.",
                    affected_component = "docker group membership",
                    remediation        = "Remove non-essential users from the docker group:\ngpasswd -d <username> docker\nConsider using Rootless Docker instead.",
                    cvss_score         = 8.0,
                )

        # Check if running in a container ourselves
        if os.path.exists("/.dockerenv"):
            yield Finding(
                title              = "SentinelScan is running INSIDE a Docker container",
                severity           = Severity.INFO,
                category           = "Containers",
                description        = "This scan is running inside a container. Some host-level checks may be limited.",
                affected_component = "Container detection",
                remediation        = "For full host scanning, run SentinelScan directly on the host.",
            )

    def _check_docker_daemon_config(self) -> Iterator[Finding]:
        self._emit_progress(22, "Checking Docker daemon configuration...")
        daemon_json_paths = [
            "/etc/docker/daemon.json",
            os.path.expanduser("~/.docker/daemon.json"),
        ]
        daemon_cfg = {}
        for p in daemon_json_paths:
            if os.path.exists(p):
                try:
                    with open(p) as f:
                        daemon_cfg = json.load(f)
                    break
                except (json.JSONDecodeError, PermissionError):
                    continue

        # Check live daemon info
        stdout, _, rc = self.run_command(["docker", "info", "--format", "{{json .}}"],
                                          timeout=15)
        if rc == 0 and stdout.strip():
            try:
                info = json.loads(stdout)
            except json.JSONDecodeError:
                info = {}
        else:
            info = {}

        # TLS verification
        if not daemon_cfg.get("tlsverify") and not info.get("ServerVersion", "").startswith("rootless"):
            yield Finding(
                title              = "Docker daemon TLS verification not configured",
                severity           = Severity.MEDIUM,
                category           = "Containers",
                description        = "Docker daemon TLS verification is not enabled. If the Docker TCP socket is exposed, anyone with network access can control the daemon.",
                affected_component = "/etc/docker/daemon.json — tlsverify",
                remediation        = "If exposing Docker TCP:\nAdd to /etc/docker/daemon.json:\n{\"tlsverify\": true, \"tlscacert\": \"/etc/docker/ca.pem\", \"tlscert\": \"/etc/docker/server-cert.pem\", \"tlskey\": \"/etc/docker/server-key.pem\"}\nOr: never expose Docker TCP — use SSH forwarding only.",
            )

        # Userland proxy
        if daemon_cfg.get("userland-proxy", True):
            yield Finding(
                title              = "Docker userland proxy is enabled",
                severity           = Severity.LOW,
                category           = "Containers",
                description        = "Docker's userland proxy adds a proxy process per port binding. Disabling it uses iptables directly, which is more efficient.",
                affected_component = "/etc/docker/daemon.json — userland-proxy",
                remediation        = "Add to /etc/docker/daemon.json:\n{\"userland-proxy\": false}",
            )

        # Check for live capabilities
        sec_opts = info.get("SecurityOptions", [])
        if sec_opts:
            seccomp = any("seccomp" in s for s in sec_opts)
            apparmor = any("apparmor" in s for s in sec_opts)
            if not seccomp:
                yield Finding(
                    title              = "Docker seccomp filtering not enabled",
                    severity           = Severity.MEDIUM,
                    category           = "Containers",
                    description        = "Docker's seccomp profile is not active. Seccomp limits the system calls containers can make, reducing the attack surface.",
                    affected_component = "Docker seccomp profile",
                    remediation        = "Enable the default seccomp profile (usually default on Docker 1.10+).\nVerify: docker info | grep seccomp",
                )

        # Check Docker version for known vulnerabilities
        version = info.get("ServerVersion", "")
        if version:
            yield Finding(
                title              = f"Docker version: {version}",
                severity           = Severity.INFO,
                category           = "Containers",
                description        = f"Docker Engine version {version}. Ensure this is a supported version.",
                affected_component = f"Docker Engine {version}",
                remediation        = "Keep Docker updated: apt-get install docker-ce",
            )

    def _check_running_containers(self) -> Iterator[Finding]:
        self._emit_progress(35, "Auditing running containers...")
        stdout, _, rc = self.run_command(
            ["docker", "ps", "--format",
             "{{json .}}"],
            timeout=15)
        if rc != 0 or not stdout.strip():
            return

        containers = []
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    containers.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        if not containers:
            yield Finding(title="No running containers", severity=Severity.INFO,
                          category="Containers",
                          description="No Docker containers are currently running.",
                          affected_component="Docker containers", remediation="No action required.")
            return

        yield Finding(
            title              = f"{len(containers)} running container(s)",
            severity           = Severity.INFO,
            category           = "Containers",
            description        = f"Running containers: {', '.join(c.get('Names','?') for c in containers[:6])}",
            affected_component = "Docker containers",
            remediation        = "Review all running containers are authorised.",
        )

        # Inspect each container for security issues
        for container in containers:
            name = container.get("Names", container.get("ID", "unknown"))
            cid  = container.get("ID", "")
            if not cid:
                continue
            yield from self._inspect_container(cid, name)

    def _inspect_container(self, cid: str, name: str) -> Iterator[Finding]:
        stdout, _, rc = self.run_command(
            ["docker", "inspect", cid], timeout=15)
        if rc != 0 or not stdout.strip():
            return
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                data = data[0]
        except (json.JSONDecodeError, IndexError):
            return

        host_cfg   = data.get("HostConfig", {})
        cfg        = data.get("Config", {})
        image      = cfg.get("Image", "unknown")
        container_name = data.get("Name", name).lstrip("/")

        # Privileged mode
        if host_cfg.get("Privileged", False):
            yield Finding(
                title              = f"Container '{container_name}' running in PRIVILEGED mode",
                severity           = Severity.CRITICAL,
                category           = "Containers",
                description        = f"Container {container_name} ({image}) is running with --privileged. A privileged container has full access to the host kernel and all devices — equivalent to root on the host.",
                affected_component = f"Container: {container_name}",
                remediation        = "Remove --privileged and add only specific capabilities needed:\ndocker run --cap-add SYS_PTRACE (example)\nNever use --privileged in production.",
                cvss_score         = 10.0,
            )

        # Running as root
        user = cfg.get("User", "")
        if not user or user == "0" or user == "root":
            yield Finding(
                title              = f"Container '{container_name}' running as root (UID 0)",
                severity           = Severity.HIGH,
                category           = "Containers",
                description        = f"Container {container_name} ({image}) runs as root user. Container breakout with root access compromises the host.",
                affected_component = f"Container user: {container_name}",
                remediation        = "Add to Dockerfile: USER nonroot\nOr run with: docker run -u 1000:1000 <image>",
                cvss_score         = 8.0,
            )

        # Read-only root filesystem
        if not host_cfg.get("ReadonlyRootfs", False):
            yield Finding(
                title              = f"Container '{container_name}' has writable root filesystem",
                severity           = Severity.MEDIUM,
                category           = "Containers",
                description        = f"Container {container_name} does not use a read-only root filesystem. A writable filesystem makes it easier for attackers to install tools and persist.",
                affected_component = f"Container filesystem: {container_name}",
                remediation        = "Use --read-only flag:\ndocker run --read-only --tmpfs /tmp <image>",
            )

        # No-new-privileges
        sec_opts = host_cfg.get("SecurityOpt", []) or []
        if not any("no-new-privileges" in s for s in sec_opts):
            yield Finding(
                title              = f"Container '{container_name}' missing --security-opt no-new-privileges",
                severity           = Severity.MEDIUM,
                category           = "Containers",
                description        = f"Container {container_name} does not have no-new-privileges set. Processes can gain additional privileges via SUID/SGID binaries inside the container.",
                affected_component = f"Container security opts: {container_name}",
                remediation        = "Run with: docker run --security-opt no-new-privileges:true <image>",
            )

        # Docker socket mounted
        binds = host_cfg.get("Binds", []) or []
        mounts = data.get("Mounts", []) or []
        all_mounts = [b.split(":")[0] for b in binds] + [m.get("Source","") for m in mounts]
        if "/var/run/docker.sock" in all_mounts:
            yield Finding(
                title              = f"Docker socket mounted into container '{container_name}'",
                severity           = Severity.CRITICAL,
                category           = "Containers",
                description        = f"Container {container_name} has /var/run/docker.sock mounted. This gives the container full control over the Docker daemon and the host — immediate full compromise.",
                affected_component = f"Container mount: {container_name} → /var/run/docker.sock",
                remediation        = "Remove the Docker socket mount. Use Docker-in-Docker (dind) or Kaniko for build use cases.",
                cvss_score         = 10.0,
            )

        # Sensitive host paths
        SENSITIVE_PATHS = {"/etc", "/proc", "/sys", "/", "/root", "/home"}
        for mount_src in all_mounts:
            if mount_src in SENSITIVE_PATHS:
                yield Finding(
                    title              = f"Sensitive host path mounted in '{container_name}': {mount_src}",
                    severity           = Severity.HIGH,
                    category           = "Containers",
                    description        = f"Container {container_name} mounts sensitive host path {mount_src}. This grants the container access to host system files.",
                    affected_component = f"Container mount: {container_name} → {mount_src}",
                    remediation        = "Avoid mounting sensitive host paths. Use named volumes instead.",
                    cvss_score         = 8.5,
                )

        # Port bindings — check for all-interface bindings
        ports = host_cfg.get("PortBindings", {}) or {}
        for cport, bindings in ports.items():
            if bindings:
                for binding in bindings:
                    host_ip = binding.get("HostIp", "0.0.0.0")
                    host_port = binding.get("HostPort", "")
                    if host_ip in ("0.0.0.0", ""):
                        yield Finding(
                            title              = f"Container '{container_name}' exposes port {host_port} on all interfaces",
                            severity           = Severity.MEDIUM,
                            category           = "Containers",
                            description        = f"Container port {cport} is bound to 0.0.0.0:{host_port}, making it accessible from any network interface.",
                            affected_component = f"Container port binding: {container_name}:{host_port}",
                            remediation        = "Bind to specific interfaces only:\ndocker run -p 127.0.0.1:{host_port}:{cport.split('/')[0]} <image>",
                        )

    def _check_docker_images(self) -> Iterator[Finding]:
        self._emit_progress(68, "Checking Docker images...")
        stdout, _, rc = self.run_command(
            ["docker", "images", "--format",
             "table {{.Repository}}\\t{{.Tag}}\\t{{.ID}}\\t{{.CreatedSince}}\\t{{.Size}}"],
            timeout=15)
        if rc != 0 or not stdout.strip():
            return

        lines = [l for l in stdout.splitlines() if l.strip() and "REPOSITORY" not in l]

        # Check for images using 'latest' tag (not pinned)
        latest_images = [l.split()[0] for l in lines if len(l.split()) >= 2 and l.split()[1] == "latest"]
        if latest_images:
            yield Finding(
                title              = f"{len(latest_images)} image(s) using 'latest' tag",
                severity           = Severity.LOW,
                category           = "Containers",
                description        = f"Images using unpinned 'latest' tag: {', '.join(latest_images[:5])}. The 'latest' tag is mutable and can pull different (potentially vulnerable) versions on rebuild.",
                affected_component = f"Docker images: {', '.join(latest_images[:3])}",
                remediation        = "Pin image versions in Dockerfile:\nFROM nginx:1.25.3\nNot: FROM nginx:latest",
            )

        # Check for very old images
        old_markers = ["years ago", "2 years", "3 years"]
        old_images = [l.split()[0] for l in lines
                      if any(m in l for m in old_markers)]
        if old_images:
            yield Finding(
                title              = f"{len(old_images)} image(s) older than 1 year",
                severity           = Severity.MEDIUM,
                category           = "Containers",
                description        = f"Old Docker images may contain unpatched vulnerabilities: {', '.join(old_images[:5])}",
                affected_component = f"Old Docker images: {', '.join(old_images[:3])}",
                remediation        = "Rebuild images from current base images:\ndocker pull <base-image>\ndocker build --no-cache -t <image> .",
            )

    def _check_docker_networks(self) -> Iterator[Finding]:
        self._emit_progress(78, "Checking Docker network configuration...")
        stdout, _, rc = self.run_command(
            ["docker", "network", "ls", "--format", "{{json .}}"],
            timeout=10)
        if rc != 0:
            return

        host_network_containers = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                net = json.loads(line)
                if net.get("Driver") == "host":
                    # Check for containers on host network
                    inspect_out, _, _ = self.run_command(
                        ["docker", "network", "inspect", net.get("ID",""), "--format",
                         "{{json .Containers}}"],
                        timeout=10)
                    if inspect_out.strip() and inspect_out.strip() not in ("{}", "null"):
                        try:
                            containers = json.loads(inspect_out)
                            if containers:
                                host_network_containers.extend(containers.keys())
                        except (json.JSONDecodeError, TypeError):
                            pass
            except (json.JSONDecodeError, TypeError):
                continue

        if host_network_containers:
            yield Finding(
                title              = f"{len(host_network_containers)} container(s) on Docker host network",
                severity           = Severity.HIGH,
                category           = "Containers",
                description        = "Containers on the 'host' network share the host's network stack with no isolation. They can bind to all host ports and access all network services.",
                affected_component = "Docker host network containers",
                remediation        = "Use bridge networks instead:\ndocker run --network bridge <image>\nOr create custom networks: docker network create mynet",
                cvss_score         = 7.0,
            )

    def _check_docker_volumes(self) -> Iterator[Finding]:
        self._emit_progress(87, "Checking for dangling/sensitive volumes...")
        stdout, _, rc = self.run_command(
            ["docker", "volume", "ls", "--filter", "dangling=true", "-q"],
            timeout=10)
        if rc == 0 and stdout.strip():
            count = len(stdout.strip().splitlines())
            yield Finding(
                title              = f"{count} dangling Docker volume(s) found",
                severity           = Severity.LOW,
                category           = "Containers",
                description        = f"{count} unused Docker volumes. Dangling volumes may contain sensitive data from deleted containers.",
                affected_component = "Docker volumes (dangling)",
                remediation        = "Review dangling volumes: docker volume ls -f dangling=true\nRemove safely: docker volume prune\n(Verify no needed data remains first)",
            )

    # ─────────────────────────────────────────────────────────────────────────
    # PODMAN
    # ─────────────────────────────────────────────────────────────────────────
    def _check_podman(self) -> Iterator[Finding]:
        self._emit_progress(90, "Checking Podman containers...")
        stdout, _, rc = self.run_command(
            ["podman", "ps", "--format", "{{.Names}} {{.Image}}"], timeout=10)
        if rc == 0 and stdout.strip():
            lines = [l for l in stdout.splitlines() if l.strip()]
            yield Finding(
                title              = f"{len(lines)} Podman container(s) running",
                severity           = Severity.INFO,
                category           = "Containers",
                description        = f"Running Podman containers: {', '.join(l.split()[0] for l in lines[:6])}",
                affected_component = "Podman containers",
                remediation        = "Ensure all running containers are authorised and up to date.",
            )

    # ─────────────────────────────────────────────────────────────────────────
    # KUBERNETES
    # ─────────────────────────────────────────────────────────────────────────
    def _check_kubernetes(self) -> Iterator[Finding]:
        self._emit_progress(93, "Checking Kubernetes configuration...")
        # Check for insecure API server
        import socket
        for port in (8080, 6443):
            try:
                s = socket.socket()
                s.settimeout(1)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    if port == 8080:
                        yield Finding(
                            title              = "Kubernetes API server exposed on insecure port 8080",
                            severity           = Severity.CRITICAL,
                            category           = "Containers",
                            description        = "Kubernetes API server is accessible on port 8080 without TLS or authentication. Full cluster control is possible without credentials.",
                            affected_component = "Kubernetes API server (insecure-port 8080)",
                            remediation        = "Disable insecure port:\nAdd to kube-apiserver flags: --insecure-port=0",
                            cvss_score         = 10.0,
                        )
                s.close()
            except Exception:
                pass

        # Check kubelet API
        try:
            s = socket.socket()
            s.settimeout(1)
            if s.connect_ex(("127.0.0.1", 10250)) == 0:
                yield Finding(
                    title              = "Kubernetes kubelet API accessible on port 10250",
                    severity           = Severity.HIGH,
                    category           = "Containers",
                    description        = "The kubelet API on port 10250 provides container management capabilities. Ensure authentication is required.",
                    affected_component = "Kubernetes kubelet port 10250",
                    remediation        = "Enforce kubelet authentication:\n--anonymous-auth=false\n--authorization-mode=Webhook",
                    cvss_score         = 8.0,
                )
            s.close()
        except Exception:
            pass

        # Check kubeconfig for default context
        kubeconfig = os.path.expanduser("~/.kube/config")
        if os.path.exists(kubeconfig):
            try:
                with open(kubeconfig) as f:
                    content = f.read()
                if "http://" in content:
                    yield Finding(
                        title              = "Kubeconfig contains insecure HTTP cluster URL",
                        severity           = Severity.HIGH,
                        category           = "Containers",
                        description        = "~/.kube/config references a cluster via HTTP (not HTTPS). All API traffic is unencrypted.",
                        affected_component = "~/.kube/config",
                        remediation        = "Update cluster server to use HTTPS in kubeconfig.",
                    )
            except PermissionError:
                pass
