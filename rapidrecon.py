#!/usr/bin/env python3
"""
RapidRecon - Simplified Version

A tool for scanning internal network subnets to identify live hosts,
open ports, common services, and potential vulnerabilities.
Generates real-time reports in CLI and HTML formats.
"""

import ipaddress
import os
import sys
import time
from datetime import datetime

# Import local modules
from scanner import NetworkScanner
from reporter import CLIReporter, HTMLReporter

def main():
    """Main function to run the RapidRecon tool."""

    # User inputs with defaults
    subnet = input("Enter subnet (CIDR format, e.g., 192.168.1.0/24): ").strip() or "192.168.1.0/24"
    ports_input = input("Enter ports to scan (comma-separated) [Default: 21,22,23,25,53,80,443,3389]: ").strip() or "21,22,23,25,53,80,443,3389"
    output_format = input("Choose output format - cli, html, or both [Default: cli]: ").strip() or "cli"
    report_file = input("Enter HTML report filename [Default: rapidrecon_report.html]: ").strip() or "rapidrecon_report.html"

    # Validate subnet
    try:
        ipaddress.ip_network(subnet)
    except ValueError as e:
        print(f"Error: Invalid subnet format - {e}")
        sys.exit(1)


    print(f"\n{'=' * 60}")
    print("RapidRecon - Network Scanning and Reporting Tool")
    print(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 60}")
    print(f"Target subnet: {subnet}")
    print(f"Ports to scan: {ports_input}")
    print(f"{'=' * 60}\n")

    try:
        # Default timeout value hardcoded
        scanner = NetworkScanner(
            subnet=subnet,
            ports=ports_input
        )

        print("Scanning network for live hosts...")
        start_time = time.time()
        scan_results = scanner.scan()
        scan_duration = time.time() - start_time

        # Output reports
        if output_format in ["cli", "both"]:
            cli_reporter = CLIReporter(scan_results, subnet, scan_duration)
            cli_reporter.generate_report()

        if output_format in ["html", "both"]:
            html_reporter = HTMLReporter(scan_results, subnet, scan_duration)
            html_path = html_reporter.generate_report(report_file)
            print(f"\nHTML report saved to: {os.path.abspath(html_path)}")

        print(f"\nScan completed in {scan_duration:.2f} seconds.")

    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
        sys.exit(0)
    except PermissionError:
        print("\nError: Some scan operations require root/administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
