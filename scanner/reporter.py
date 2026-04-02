"""
Output formatters: console table, JSON, CSV.
"""

import json
import csv
import io
from scanner.core import HostResult


# ──────────────────── ANSI Colors ────────────────────

class Colors:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    DIM    = "\033[2m"


# ──────────────────── Console Table ──────────────────

def print_results(results: list[HostResult], show_closed: bool = False) -> None:
    """Pretty-print scan results to the console."""

    banner = f"""
{Colors.CYAN}{Colors.BOLD}
  ╔═══════════════════════════════════════╗
  ║         P O R T   S C A N N E R       ║
  ╚═══════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)

    for host in results:
        open_ports = host.open_ports

        header = f"  {Colors.BOLD}Target:{Colors.RESET} {host.ip}"
        if host.hostname:
            header += f" ({host.hostname})"
        print(header)

        if host.os_guess:
            print(f"  {Colors.BOLD}OS Guess:{Colors.RESET} {host.os_guess}")

        print(f"  {Colors.BOLD}Scan Time:{Colors.RESET} {host.scan_time:.2f}s")
        print(f"  {Colors.BOLD}Open Ports:{Colors.RESET} {len(open_ports)}")
        print()

        if not open_ports:
            print(f"  {Colors.YELLOW}No open ports found.{Colors.RESET}")
            print()
            continue

        # Table header
        print(f"  {'PORT':<10} {'STATE':<10} {'SERVICE':<18} {'BANNER'}")
        print(f"  {'─'*10} {'─'*10} {'─'*18} {'─'*40}")

        for p in open_ports:
            state_colored = f"{Colors.GREEN}open{Colors.RESET}"
            banner_text = p.banner[:55] + "…" if len(p.banner) > 55 else p.banner
            print(
                f"  {p.port:<10} {state_colored:<19} {p.service:<18} "
                f"{Colors.DIM}{banner_text}{Colors.RESET}"
            )

        print()

    # Summary
    total_open = sum(len(h.open_ports) for h in results)
    total_hosts = len(results)
    print(f"  {Colors.BOLD}Summary:{Colors.RESET} "
          f"Scanned {total_hosts} host(s), "
          f"found {total_open} open port(s).")
    print()


# ──────────────────── JSON Export ─────────────────────

def export_json(results: list[HostResult], filepath: str) -> None:
    """Export results to a JSON file."""
    data = {
        "scan_results": [h.to_dict() for h in results],
        "summary": {
            "hosts_scanned": len(results),
            "total_open_ports": sum(len(h.open_ports) for h in results),
        },
    }
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  [✓] Results saved to {filepath}")


# ──────────────────── CSV Export ──────────────────────

def export_csv(results: list[HostResult], filepath: str) -> None:
    """Export results to a CSV file."""
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Hostname", "Port", "State", "Service", "Banner"])
        for host in results:
            for p in host.open_ports:
                writer.writerow([
                    host.ip, host.hostname,
                    p.port, p.state, p.service, p.banner,
                ])
    print(f"  [✓] Results saved to {filepath}")
