"""
Advanced DNS Lookup Tool
Author: HackerAI
Description: Multithreaded DNS enumeration supporting A, AAAA, MX, NS, TXT,
             CNAME, SOA, SRV, CAA, and PTR records with JSON/CSV output.
"""

import argparse
import json
import csv
import sys
import socket
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any

try:
    import dns.resolver
    import dns.exception
    import dns.rdatatype
    import dns.reversename
except ImportError:
    print("[!] Required library 'dnspython' is not installed.")
    print("    Install it with: pip install dnspython")
    sys.exit(1)


# ── Configuration ────────────────────────────────────────────────────────────
DEFAULT_TIMEOUT = 5.0
DEFAULT_THREADS = 20
DEFAULT_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

# Named records (tuple = (display_name, rdatatype))
RECORD_REGISTRY: Dict[str, str] = {
    "A":      "A",
    "AAAA":   "AAAA",
    "MX":     "MX",
    "NS":     "NS",
    "TXT":    "TXT",
    "CNAME":  "CNAME",
    "SOA":    "SOA",
    "SRV":    "SRV",
    "CAA":    "CAA",
    "NAPTR":  "NAPTR",
    "PTR":    "PTR",
}


# ── Lookup Engine ────────────────────────────────────────────────────────────
def resolve_record(
    domain: str,
    record_type: str,
    nameserver: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> List[str]:
    """
    Query a single DNS record type for a domain.
    Returns a list of answer strings, or an empty list on failure.
    """
    resolver = dns.resolver.Resolver(configure=True)
    if nameserver:
        resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        answers = resolver.resolve(domain, record_type, raise_on_no_answer=True)
        return [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except dns.exception.DNSException:
        return []
    except Exception:
        return []


def reverse_lookup(ip_address: str, timeout: float = DEFAULT_TIMEOUT) -> List[str]:
    """Perform a PTR reverse lookup for an IP address."""
    try:
        rev_name = dns.reversename.from_address(ip_address)
        return resolve_record(str(rev_name), "PTR", timeout=timeout)
    except (dns.exception.DNSException, ValueError):
        return []


def lookup_domain(
    domain: str,
    record_types: Optional[List[str]] = None,
    nameserver: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    reverse: bool = False,
) -> Dict[str, Any]:
    """
    Full multirecord lookup for a single domain.

    Returns a dict:
        {
            "domain": str,
            "records": { "A": [...], "AAAA": [...], ... },
            "error": Optional[str]
        }
    """
    if record_types is None:
        record_types = DEFAULT_RECORD_TYPES

    result: Dict[str, Any] = {
        "domain": domain,
        "records": {},
        "error": None,
    }

    for rtype in record_types:
        rtype_upper = rtype.upper()
        if rtype_upper not in RECORD_REGISTRY:
            continue
        records = resolve_record(domain, RECORD_REGISTRY[rtype_upper], nameserver, timeout)
        if records:
            result["records"][rtype_upper] = records

    # Optional reverse (PTR) on A records
    if reverse and "A" in result.get("records", {}):
        ptrs: List[str] = []
        for ip in result["records"]["A"]:
            ptrs.extend(reverse_lookup(ip, timeout))
        if ptrs:
            result["records"]["PTR"] = ptrs

    return result


def batch_lookup(
    domains: List[str],
    record_types: Optional[List[str]] = None,
    nameserver: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    reverse: bool = False,
    threads: int = DEFAULT_THREADS,
) -> List[Dict[str, Any]]:
    """Concurrently resolve multiple domains."""
    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(lookup_domain, d, record_types, nameserver, timeout, reverse): d
            for d in domains
        }
        for future in as_completed(futures):
            dom = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({"domain": dom, "records": {}, "error": str(exc)})
    return results


# ── Output Formatters ────────────────────────────────────────────────────────
def print_results(results: List[Dict[str, Any]], color: bool = True) -> None:
    """Pretty-print lookup results to stdout."""
    for i, entry in enumerate(results):
        domain = entry["domain"]
        error = entry.get("error")
        records = entry.get("records", {})

        if color:
            _c = _colorize
        else:
            _c = lambda s, *a: s

        if error:
            print(f"\n{_c('[✗]', 'red')} {_c(domain, 'cyan')} — {_c(error, 'yellow')}")
            continue

        print(f"\n{_c('[✓]', 'green')} {_c(domain, 'cyan')}")
        if not records:
            print(f"  {_c('(no records found)', 'yellow')}")

        for rtype in RECORD_REGISTRY:
            if rtype in records:
                for rdata in records[rtype]:
                    print(f"  {_c(f'{rtype:6}', 'magenta')} {rdata}")

        if i < len(results) - 1:
            print()


def _colorize(text: str, color: str) -> str:
    """Wrap text in ANSI color codes."""
    colors = {
        "red":     "\033[91m",
        "green":   "\033[92m",
        "yellow":  "\033[93m",
        "cyan":    "\033[96m",
        "magenta": "\033[95m",
        "reset":   "\033[0m",
    }
    return f"{colors.get(color, colors['reset'])}{text}{colors['reset']}"


def export_json(results: List[Dict[str, Any]], filepath: str) -> None:
    """Write results to a JSON file."""
    with open(filepath, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] JSON results written to {filepath}")


def export_csv(results: List[Dict[str, Any]], filepath: str) -> None:
    """Flatten results into CSV (domain, type, value)."""
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "record_type", "value"])
        for entry in results:
            domain = entry["domain"]
            records = entry.get("records", {})
            for rtype, values in records.items():
                for val in values:
                    writer.writerow([domain, rtype, val])
    print(f"[+] CSV results written to {filepath}")


# ── CLI Entrypoint ───────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Advanced DNS Lookup Tool — multithreaded, multirecord enumeration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python dns_lookup.py example.com\n"
            "  python dns_lookup.py example.com -t A MX NS TXT\n"
            "  python dns_lookup.py example.com -n 8.8.8.8 -r\n"
            "  python dns_lookup.py -f domains.txt -o results.json\n"
        ),
    )

    # Target specification
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("domain", nargs="?", help="Domain name to look up")
    target.add_argument("-f", "--file", help="File containing domains (one per line)")

    # Record types
    parser.add_argument(
        "-t", "--types",
        nargs="+",
        default=DEFAULT_RECORD_TYPES,
        help=f"Record types to query (default: {' '.join(DEFAULT_RECORD_TYPES)})",
    )

    # Options
    parser.add_argument("-n", "--nameserver", help="Custom DNS nameserver (e.g., 8.8.8.8)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Query timeout (default: {DEFAULT_TIMEOUT}s)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help=f"Thread count (default: {DEFAULT_THREADS})")
    parser.add_argument("-r", "--reverse", action="store_true", help="Perform reverse (PTR) lookup on A records")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    # Export
    parser.add_argument("-o", "--output", help="Export results to file (JSON or CSV based on extension)")
    parser.add_argument("--csv", action="store_true", help="Force CSV output format (requires -o)")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Collect domains
    if args.file:
        if not os.path.isfile(args.file):
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
        with open(args.file) as f:
            domains = [line.strip() for line in f if line.strip()]
        if not domains:
            print("[!] No domains found in file.")
            sys.exit(1)
    else:
        domains = [args.domain.strip()] if args.domain else []

    # Validate record types
    valid_types = []
    for rt in args.types:
        rt_upper = rt.upper()
        if rt_upper in RECORD_REGISTRY:
            valid_types.append(rt_upper)
        else:
            print(f"[!] Unknown record type '{rt}', skipping.")

    if not valid_types:
        print("[!] No valid record types specified.")
        sys.exit(1)

    # Run lookups
    print(f"[*] Resolving {len(domains)} domain(s)...\n")
    results = batch_lookup(
        domains=domains,
        record_types=valid_types,
        nameserver=args.nameserver,
        timeout=args.timeout,
        reverse=args.reverse,
        threads=args.threads,
    )

    # Output
    print_results(results, color=not args.no_color)

    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if args.csv or ext == ".csv":
            export_csv(results, args.output)
        elif ext == ".json":
            export_json(results, args.output)
        else:
            # Default to JSON
            export_json(results, args.output)


if __name__ == "__main__":
    main()