#!/usr/bin/env python3
"""
PortScanner — A multi-threaded TCP port scanner.

Usage:
    python main.py -t <target> [options]

Examples:
    python main.py -t 192.168.1.1 -p 1-1024
    python main.py -t 10.0.0.0/24 -p 22,80,443 --threads 200
    sudo python main.py -t 192.168.1.1 --top-ports 100 --syn --banners
"""

import argparse
import sys
import os
import time

from scanner.core import PortScanner, ScanConfig, parse_ports
from scanner.services import get_top_ports
from scanner.reporter import print_results, export_json, export_csv


# ──────────────────── Progress Bar ───────────────────

def progress_callback(completed: int, total: int) -> None:
    """Display a live progress bar in the terminal."""
    pct = completed / total * 100
    bar_len = 40
    filled = int(bar_len * completed // total)
    bar = "█" * filled + "░" * (bar_len - filled)
    sys.stdout.write(f"\r  Scanning: |{bar}| {pct:5.1f}%  ({completed}/{total})")
    sys.stdout.flush()
    if completed == total:
        print()  # newline when done


# ──────────────────── CLI ────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscanner",
        description="🔍 A fast, multi-threaded TCP port scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -t 192.168.1.1 -p 22,80,443
  %(prog)s -t 10.0.0.1 -p 1-65535 --threads 500
  %(prog)s -t 192.168.1.0/24 --top-ports 100 --banners
  sudo %(prog)s -t 192.168.1.1 --syn -p 1-1024

⚠️  Only scan targets you are authorized to test.
        """,
    )

    parser.add_argument(
        "-t", "--target", required=True,
        help="Target IP, hostname, CIDR (192.168.1.0/24), or range (192.168.1.1-50)",
    )
    parser.add_argument(
        "-p", "--ports", default=None,
        help="Port(s) to scan: 80 | 22,80,443 | 1-1024 | 22,80,100-200",
    )
    parser.add_argument(
        "--top-ports", type=int, default=None, metavar="N",
        help="Scan top N most common ports (e.g., 100, 1000)",
    )
    parser.add_argument(
        "--threads", type=int, default=100,
        help="Number of concurrent threads (default: 100)",
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Socket timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--syn", action="store_true",
        help="Use SYN scan (requires root/admin + scapy)",
    )
    parser.add_argument(
        "--banners", action="store_true",
        help="Attempt to grab service banners",
    )
    parser.add_argument(
        "--os", action="store_true", dest="os_detect",
        help="Enable basic OS detection via TTL",
    )
    parser.add_argument(
        "-o", "--output", default=None, metavar="FILE",
        help="Save results to file (.json or .csv)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output during scan",
    )
    parser.add_argument(
        "--no-progress", action="store_true",
        help="Disable the progress bar",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # ── Determine ports ──
    if args.ports and args.top_ports:
        parser.error("Cannot use both --ports and --top-ports.")

    if args.top_ports:
        ports = get_top_ports(args.top_ports)
    elif args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            parser.error(f"Invalid port specification: {args.ports}")
    else:
        ports = get_top_ports(100)  # default

    # ── SYN check ──
    if args.syn and os.geteuid() != 0:
        print("[!] SYN scan requires root privileges. Use sudo.")
        sys.exit(1)

    # ── Build config ──
    config = ScanConfig(
        targets=[args.target],
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        technique="syn" if args.syn else "connect",
        grab_banners=args.banners,
        os_detection=args.os_detect,
        verbose=args.verbose,
        callback=None if (args.verbose or args.no_progress) else progress_callback,
    )

    # ── Run scan ──
    scanner = PortScanner(config)

    try:
        results = scanner.run()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(130)

    # ── Output ──
    print_results(results)

    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".json":
            export_json(results, args.output)
        elif ext == ".csv":
            export_csv(results, args.output)
        else:
            export_json(results, args.output)


if __name__ == "__main__":
    main()
