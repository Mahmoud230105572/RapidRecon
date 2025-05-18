#!/usr/bin/env python3
"""
RapidRecon - Nmap Network Scanner Module

Scans network subnets using python-nmap to identify live hosts,
open ports, and services.
"""

import nmap

# Common service mapping
COMMON_SERVICES = {
    21: {"name": "FTP", "risk": "Medium"},
    22: {"name": "SSH", "risk": "Low"},
    23: {"name": "Telnet", "risk": "High"},
    25: {"name": "SMTP", "risk": "Medium"},
    53: {"name": "DNS", "risk": "Low"},
    80: {"name": "HTTP", "risk": "Medium"},
    110: {"name": "POP3", "risk": "Medium"},
    135: {"name": "MS-RPC", "risk": "Medium"},
    139: {"name": "NetBIOS", "risk": "Medium"},
    143: {"name": "IMAP", "risk": "Medium"},
    443: {"name": "HTTPS", "risk": "Low"},
    445: {"name": "SMB", "risk": "Medium"},
    993: {"name": "IMAPS", "risk": "Low"},
    995: {"name": "POP3S", "risk": "Low"},
    1723: {"name": "PPTP", "risk": "Medium"},
    3306: {"name": "MySQL", "risk": "Medium"},
    3389: {"name": "RDP", "risk": "Medium"},
    5900: {"name": "VNC", "risk": "Medium"},
    8080: {"name": "HTTP-Proxy", "risk": "Medium"}
}


class NetworkScanner:
    """Network scanner using only Nmap."""

    def __init__(self, subnet, ports=None):
        """
        Args:
            subnet (str): Subnet in CIDR notation (e.g., '192.168.1.0/24')
            ports (list): Ports to scan (default: common ports)
        """
        self.subnet = subnet
        self.ports = ports

    def scan(self):
        """Run Nmap scan on the subnet."""
        results = {}
        try:
            nm = nmap.PortScanner()
            print(f"[+] Starting Nmap scan on {self.subnet} (ports: {self.ports})")

            nm.scan(hosts=self.subnet, arguments=f"-p {self.ports} -sV --open")

            for host in nm.all_hosts():
                results[host] = {"ports": []}
                for proto in nm[host].all_protocols():
                    for port in sorted(nm[host][proto].keys()):
                        info = nm[host][proto][port]
                        service = info.get('name', 'unknown')
                        version = (info.get('product', '') + ' ' + info.get('version', '')).strip()
                        risk = COMMON_SERVICES.get(port, {}).get("risk", "Unknown")

                        results[host]["ports"].append({
                            "port": port,
                            "service": service,
                            "version": version,
                            "risk": risk
                        })
            return results
        except Exception as e:
            print(f"[!] Nmap scan error: {e}")
            return {}


'''
result dictionary contains the data in this format

{
  '192.168.1.10': {
    'ports': [
      {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.4', 'risk': 'Low'},
      {'port': 80, 'service': 'http', 'version': 'Apache 2.4.41', 'risk': 'Medium'}
    ]
  }
}


'''

# Example usage
if __name__ == "__main__":
    scanner = NetworkScanner("192.168.1.0/24")
    result = scanner.scan()
    for host, data in result.items():
        print(f"\nHost: {host}")
        for port in data["ports"]:
            print(f"  Port {port['port']}: {port['service']} ({port['version']}) - Risk: {port['risk']}")
