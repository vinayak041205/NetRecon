#!/usr/bin/env python3
"""
Network Reconnaissance & Vulnerability Banner Grabber
Author: Security Engineering Sprint
License: MIT
Description:
    A multi-threaded network scanner that probes TCP ports, extracts service banners,
    parses TLS/SSL certificate details, flags known CVEs based on service signatures,
    and exports findings to stdout, JSON, and CSV formats.
"""

import socket
import ssl
import argparse
import sys
import os
import re
import json
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Standard high-priority TCP ports
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1524, 1723, 2121, 3306, 3389, 5432, 5900, 6667, 8080, 8443
]

# Signature heuristics mapping common vulnerable banners to known CVEs
CVE_DATABASE = [
    {
        "pattern": r"vsFTPd 2\.3\.4",
        "cve": "CVE-2011-2523",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "title": "vsFTPd 2.3.4 Malicious Backdoor Execution",
        "description": "The vsFTPd 2.3.4 archive contained a backdoor triggered by a smiley face inside the username string."
    },
    {
        "pattern": r"Unreal3\.2\.8\.1",
        "cve": "CVE-2010-2075",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "title": "UnrealIRCd 3.2.8.1 Remote Code Execution Backdoor",
        "description": "A Trojaned version of UnrealIRCd allowed root remote command execution via specific DEBUG strings."
    },
    {
        "pattern": r"OpenSSH_4\.7p1",
        "cve": "CVE-2008-0166",
        "severity": "HIGH",
        "cvss": 7.8,
        "title": "Debian Predictable PRNG (Weak SSH Keys)",
        "description": "OpenSSH built against a patched Debian OpenSSL library generates weak predictable cryptographic keys."
    },
    {
        "pattern": r"Apache/2\.2\.8",
        "cve": "CVE-2008-0455",
        "severity": "MEDIUM",
        "cvss": 5.0,
        "title": "Apache 2.2.8 mod_negotiation Information Disclosure",
        "description": "Outdated Apache server branch vulnerable to cross-site scripting and path disclosure through mod_negotiation."
    },
    {
        "pattern": r"PHP/5\.2\.4",
        "cve": "CVE-2012-1823",
        "severity": "HIGH",
        "cvss": 7.5,
        "title": "PHP-CGI Query String Parameter Argument Injection",
        "description": "Legacy PHP versions expose source code or allow command execution when operated in CGI mode."
    },
    {
        "pattern": r"Microsoft-IIS/6\.0",
        "cve": "CVE-2017-7269",
        "severity": "HIGH",
        "cvss": 8.5,
        "title": "Windows Server 2003 IIS 6.0 WebDAV Buffer Overflow",
        "description": "Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Microsoft IIS 6.0."
    },
    {
        "pattern": r"root shell|#|ingreslock",
        "cve": "UNMAPPED-ROOT-SHELL",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "title": "Unauthenticated Remote Root Shell Access",
        "description": "The service returned a naked interactive root shell prompt directly upon TCP connection."
    }
]


def match_cves(banner: str) -> list:
    """Matches grabbed banner text against signature heuristics."""
    matches = []
    if not banner:
        return matches

    for entry in CVE_DATABASE:
        if re.search(entry["pattern"], banner, re.IGNORECASE):
            matches.append({
                "cve": entry["cve"],
                "severity": entry["severity"],
                "cvss": entry["cvss"],
                "title": entry["title"],
                "description": entry["description"]
            })
    return matches


def grab_tls_details(target: str, port: int, timeout: float) -> str:
    """Performs a TLS handshake on SSL/TLS ports and extracts certificate metadata."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((target, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=target) as tls_sock:
                tls_version = tls_sock.version()
                cipher = tls_sock.cipher()
                cert = tls_sock.getpeercert(binary_form=False)

                subject = "Unknown"
                if cert and "subject" in cert:
                    for item in cert["subject"]:
                        for key, val in item:
                            if key == "commonName":
                                subject = val

                cipher_name = cipher[0] if cipher else "Unknown"
                return f"TLS: {tls_version} | Cipher: {cipher_name} | Subject CN: {subject}"
    except Exception:
        return ""


def grab_plain_banner(target: str, port: int, timeout: float) -> str:
    """Attempts connection and retrieves plain service banners using protocol triggers."""
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))

            # Send protocol-specific probes
            if port in [80, 8080]:
                payload = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: SecRecon/2.0\r\nConnection: close\r\n\r\n"
                s.sendall(payload.encode())
            else:
                # Generic trigger for FTP, SSH, Telnet, SMTP
                s.sendall(b"\r\n")

            data = s.recv(1024)
            banner = data.decode("utf-8", errors="ignore").strip()
    except (socket.timeout, socket.error):
        pass

    return banner


def scan_port(target: str, port: int, timeout: float) -> dict:
    """Checks if a TCP port is open, grabs banners/TLS info, and checks CVE signatures."""
    result = {
        "port": port,
        "state": "closed",
        "banner": "",
        "tls_info": "",
        "cves": []
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((target, port)) != 0:
                return result
            result["state"] = "open"
    except socket.error:
        return result

    # Check TLS for secure ports
    if port in [443, 8443]:
        tls_info = grab_tls_details(target, port, timeout)
        result["tls_info"] = tls_info
        if tls_info:
            result["banner"] = tls_info

    # Fall back to standard banner grabbing
    if not result["banner"]:
        banner = grab_plain_banner(target, port, timeout)
        result["banner"] = banner

    # Run CVE correlation
    if result["banner"]:
        result["cves"] = match_cves(result["banner"])

    return result


def parse_ports(port_arg: str) -> list:
    """Parses port ranges (e.g. '21-100') or comma-separated lists ('22,80,443')."""
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))


def write_json_report(filepath: str, metadata: dict, findings: list):
    """Exports structured scan results to a JSON file."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    report_data = {
        "metadata": metadata,
        "results": findings
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
    print(f"[+] JSON report successfully written to: {filepath}")


def write_csv_report(filepath: str, metadata: dict, findings: list):
    """Exports scan results to a flat CSV file for spreadsheet analysis."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Target", "Timestamp", "Port", "State", "Banner", "CVE", "Severity", "CVSS", "Title"])
        for item in findings:
            clean_banner = item["banner"].replace("\r", " ").replace("\n", " ")
            if item["cves"]:
                for cve in item["cves"]:
                    writer.writerow([
                        metadata["target"], metadata["timestamp"], item["port"],
                        item["state"], clean_banner, cve["cve"], cve["severity"],
                        cve["cvss"], cve["title"]
                    ])
            else:
                writer.writerow([
                    metadata["target"], metadata["timestamp"], item["port"],
                    item["state"], clean_banner, "None", "None", "None", "None"
                ])
    print(f"[+] CSV report successfully written to:  {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Threaded TCP Port Scanner, Banner Grabber & CVE Mapper",
        epilog="Example: python3 recon_grabber.py 192.168.1.105 -p 1-1000 -t 100 -oJ reports/scan.json"
    )
    parser.add_argument("target", help="Target IP address or domain name")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g. '21-100' or '22,80,443'). Default: common ports", default=None)
    parser.add_argument("-t", "--threads", help="Number of concurrent worker threads (Default: 50)", type=int, default=50)
    parser.add_argument("-w", "--timeout", help="Socket timeout in seconds (Default: 1.5)", type=float, default=1.5)
    parser.add_argument("-oJ", "--output-json", help="Path to write JSON report output (e.g. reports/scan.json)", default=None)
    parser.add_argument("-oC", "--output-csv", help="Path to write CSV report output (e.g. reports/scan.csv)", default=None)

    args = parser.parse_args()

    # Resolve target hostname
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname '{args.target}'")
        sys.exit(1)

    ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    start_time = datetime.now()

    print("=" * 75)
    print(f"Target:        {args.target} ({target_ip})")
    print(f"Ports Queued:  {len(ports)}")
    print(f"Threads:       {args.threads}")
    print(f"Scan Started:  {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 75)
    print(f"{'PORT':<8} {'STATE':<8} {'BANNER / SERVICE DETAILS':<45}")
    print("-" * 75)

    open_ports_data = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, target_ip, p, args.timeout): p for p in ports}

        for future in as_completed(futures):
            res = future.result()
            if res["state"] == "open":
                open_ports_data.append(res)
                clean_banner = res["banner"].replace("\r", " ").replace("\n", " ")[:45]
                print(f"{res['port']:<8} {'OPEN':<8} {clean_banner or '[No banner returned]'}")

                for cve in res["cves"]:
                    print(f"  └─> [!] [{cve['severity']}] {cve['cve']} (CVSS {cve['cvss']}): {cve['title']}")

    # Sort results by port number
    open_ports_data.sort(key=lambda x: x["port"])
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print("-" * 75)
    print(f"Scan complete in {duration:.2f} seconds.")
    print(f"Total open ports discovered: {len(open_ports_data)}")

    # Handle Exports
    metadata = {
        "target": args.target,
        "target_ip": target_ip,
        "ports_scanned": len(ports),
        "open_ports_found": len(open_ports_data),
        "timestamp": start_time.isoformat(),
        "duration_seconds": round(duration, 2)
    }

    if args.output_json:
        write_json_report(args.output_json, metadata, open_ports_data)

    if args.output_csv:
        write_csv_report(args.output_csv, metadata, open_ports_data)


if __name__ == "__main__":
    main()