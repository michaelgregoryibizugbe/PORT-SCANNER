"""
Core scanner engine — coordinates threads and manages results.
"""

import socket
import time
import ipaddress
import concurrent.futures
from dataclasses import dataclass, field
from typing import Callable

from scanner.techniques import tcp_connect_scan, syn_scan, grab_banner, detect_os_ttl
from scanner.services import get_service_name, get_top_ports


# ──────────────────────────── Data Models ────────────────────────────

@dataclass
class PortResult:
    """Result of scanning a single port."""
    port: int
    state: str  # "open", "closed", "filtered"
    service: str = "unknown"
    banner: str = ""

    def to_dict(self) -> dict:
        d = {"port": self.port, "state": self.state, "service": self.service}
        if self.banner:
            d["banner"] = self.banner
        return d


@dataclass
class HostResult:
    """Aggregated results for one host."""
    ip: str
    hostname: str = ""
    os_guess: str = ""
    scan_time: float = 0.0
    ports: list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "open"]

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "os_guess": self.os_guess,
            "scan_time_sec": round(self.scan_time, 2),
            "open_ports": [p.to_dict() for p in self.open_ports],
        }


@dataclass
class ScanConfig:
    """Scanner configuration."""
    targets: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    threads: int = 100
    timeout: float = 1.0
    technique: str = "connect"  # "connect" or "syn"
    grab_banners: bool = False
    os_detection: bool = False
    verbose: bool = False
    callback: Callable | None = None  # progress callback


# ──────────────────────────── Helpers ────────────────────────────────

def resolve_targets(raw: str) -> list[str]:
    """
    Expand a target string into a list of IP addresses.

    Supports:
      - Single IP:   192.168.1.1
      - CIDR:        192.168.1.0/24
      - Range:       192.168.1.1-50
      - Hostname:    example.com
    """
    raw = raw.strip()
    ips: list[str] = []

    # CIDR notation
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
            ips = [str(h) for h in network.hosts()]
            return ips if ips else [str(network.network_address)]
        except ValueError:
            pass

    # Dash range: 192.168.1.1-50
    if "-" in raw:
        parts = raw.rsplit("-", 1)
        try:
            base_ip = ipaddress.ip_address(parts[0])
            end = int(parts[1])
            start = int(str(base_ip).split(".")[-1])
            prefix = ".".join(str(base_ip).split(".")[:-1])
            for i in range(start, end + 1):
                ips.append(f"{prefix}.{i}")
            return ips
        except (ValueError, IndexError):
            pass

    # Single IP
    try:
        ipaddress.ip_address(raw)
        return [raw]
    except ValueError:
        pass

    # Hostname → resolve
    try:
        ip = socket.gethostbyname(raw)
        return [ip]
    except socket.gaierror:
        raise ValueError(f"Cannot resolve target: {raw}")


def parse_ports(port_str: str) -> list[int]:
    """
    Parse port specification string.

    Examples:
      "80"          → [80]
      "22,80,443"   → [22, 80, 443]
      "1-1024"      → [1, 2, ..., 1024]
      "22,80,100-200,443"  → mixed
    """
    ports: set[int] = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            for p in range(int(start), int(end) + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


# ──────────────────────────── Scanner ────────────────────────────────

class PortScanner:
    """
    Multi-threaded port scanner engine.

    Usage:
        config = ScanConfig(
            targets=["192.168.1.1"],
            ports=[22, 80, 443],
            threads=100,
        )
        scanner = PortScanner(config)
        results = scanner.run()
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self._total_tasks = 0
        self._completed = 0

    def run(self) -> list[HostResult]:
        """Execute the scan and return results for all hosts."""
        all_results: list[HostResult] = []

        for target in self.config.targets:
            try:
                hosts = resolve_targets(target)
            except ValueError as e:
                if self.config.verbose:
                    print(f"[!] {e}")
                continue

            for host in hosts:
                result = self._scan_host(host)
                all_results.append(result)

        return all_results

    def _scan_host(self, host: str) -> HostResult:
        """Scan all configured ports on a single host."""
        start = time.perf_counter()

        # Reverse DNS
        hostname = ""
        try:
            hostname = socket.getfqdn(host)
            if hostname == host:
                hostname = ""
        except Exception:
            pass

        if self.config.verbose:
            print(f"\n[*] Scanning {host}" + (f" ({hostname})" if hostname else ""))
            print(f"    Ports: {len(self.config.ports)} | "
                  f"Threads: {self.config.threads} | "
                  f"Technique: {self.config.technique.upper()}")

        # Choose scan function
        if self.config.technique == "syn":
            scan_fn = syn_scan
        else:
            scan_fn = tcp_connect_scan

        # Thread pool scanning
        port_results: list[PortResult] = []
        self._total_tasks = len(self.config.ports)
        self._completed = 0

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.threads
        ) as executor:
            future_to_port = {
                executor.submit(
                    self._probe_port, scan_fn, host, port
                ): port
                for port in self.config.ports
            }

            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    port_results.append(result)

                self._completed += 1
                if self.config.callback:
                    self.config.callback(self._completed, self._total_tasks)

        # Sort by port number
        port_results.sort(key=lambda r: r.port)

        elapsed = time.perf_counter() - start

        # OS detection
        os_guess = ""
        if self.config.os_detection:
            os_guess = detect_os_ttl(host)

        host_result = HostResult(
            ip=host,
            hostname=hostname,
            os_guess=os_guess,
            scan_time=elapsed,
            ports=port_results,
        )

        return host_result

    def _probe_port(
        self,
        scan_fn: Callable,
        host: str,
        port: int,
    ) -> PortResult | None:
        """Probe a single port — scan + optional banner grab."""
        is_open = scan_fn(host, port, self.config.timeout)

        if not is_open:
            return None  # only return open ports

        service = get_service_name(port)
        banner = ""

        if self.config.grab_banners:
            banner = grab_banner(host, port, timeout=self.config.timeout + 1)

            # Try to refine service name from banner
            if banner and service == "unknown":
                service = self._identify_from_banner(banner)

        if self.config.verbose:
            line = f"    [+] {port:<6} open  {service}"
            if banner:
                line += f"  │ {banner[:60]}"
            print(line)

        return PortResult(
            port=port,
            state="open",
            service=service,
            banner=banner,
        )

    @staticmethod
    def _identify_from_banner(banner: str) -> str:
        """Guess service from banner content."""
        bl = banner.lower()
        signatures = {
            "ssh": "SSH", "openssh": "SSH",
            "http": "HTTP", "apache": "Apache",
            "nginx": "Nginx", "iis": "IIS",
            "ftp": "FTP", "vsftpd": "vsftpd", "proftpd": "ProFTPD",
            "smtp": "SMTP", "postfix": "Postfix", "exim": "Exim",
            "mysql": "MySQL", "mariadb": "MariaDB",
            "postgresql": "PostgreSQL",
            "redis": "Redis",
            "mongodb": "MongoDB",
            "elastic": "Elasticsearch",
        }
        for keyword, name in signatures.items():
            if keyword in bl:
                return name
        return "unknown"
