"""
Scanning techniques: TCP Connect, SYN (half-open), and Banner Grabbing.
"""

import socket
import struct
import os

# Optional: scapy for SYN scanning
try:
    from scapy.all import IP, TCP, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def tcp_connect_scan(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    TCP full-connect scan.
    Completes the 3-way handshake — works without root.

    Returns True if port is open.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    except (socket.timeout, OSError):
        return False
    finally:
        sock.close()


def syn_scan(host: str, port: int, timeout: float = 1.5) -> bool:
    """
    TCP SYN (half-open) scan using Scapy.
    Sends SYN, checks for SYN-ACK. Does NOT complete handshake.
    Requires root/admin privileges.

    Returns True if port is open.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError(
            "Scapy is required for SYN scanning. "
            "Install with: pip install scapy"
        )

    conf.verb = 0  # suppress scapy output
    src_port = 40000 + (os.getpid() % 25000)

    pkt = IP(dst=host) / TCP(sport=src_port, dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        return False  # filtered / no response

    if resp.haslayer(TCP):
        tcp_layer = resp.getlayer(TCP)
        flags = tcp_layer.flags

        # SYN-ACK → open
        if flags == 0x12:
            # Send RST to tear down (be polite)
            rst = IP(dst=host) / TCP(
                sport=src_port, dport=port, flags="R",
                seq=resp.ack
            )
            sr1(rst, timeout=0.5, verbose=0)
            return True

        # RST → closed
        if flags & 0x04:
            return False

    return False


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """
    Connect to a port and attempt to read a service banner.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))

        # Some services send banner immediately; others need a nudge
        if port in (80, 443, 8080, 8443):
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % host.encode())
        elif port in (21, 22, 25, 110, 143):
            pass  # these typically send a banner on connect
        else:
            sock.sendall(b"\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        return banner[:256]  # truncate
    except (socket.timeout, OSError, ConnectionRefusedError):
        return ""
    finally:
        sock.close()


def detect_os_ttl(host: str, timeout: float = 2.0) -> str:
    """
    Basic OS guess based on ICMP TTL value.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, 80))  # need at least one open port
        # Use IP header TTL from a raw perspective — simplified
        ttl = None
        sock.close()

        # Alternative: use ping
        if os.name == "nt":
            import subprocess
            out = subprocess.run(
                ["ping", "-n", "1", "-w", "1000", host],
                capture_output=True, text=True, timeout=5
            )
            for line in out.stdout.splitlines():
                if "TTL=" in line or "ttl=" in line:
                    ttl = int(line.split("TTL=")[-1].split("ttl=")[-1].split()[0])
        else:
            import subprocess
            out = subprocess.run(
                ["ping", "-c", "1", "-W", "1", host],
                capture_output=True, text=True, timeout=5
            )
            for line in out.stdout.splitlines():
                if "ttl=" in line.lower():
                    parts = line.lower().split("ttl=")
                    ttl = int(parts[1].split()[0])

        if ttl is None:
            return "Unknown"
        elif ttl <= 64:
            return f"Linux/Unix (TTL={ttl})"
        elif ttl <= 128:
            return f"Windows (TTL={ttl})"
        else:
            return f"Network Device (TTL={ttl})"

    except Exception:
        return "Unknown"
