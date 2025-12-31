#!/usr/bin/env python3
"""
Advanced Ethical Network Security Scanner
A comprehensive tool for authorized network security assessment and monitoring
"""

import socket
import time
import sys
import argparse
from datetime import datetime
import json
from concurrent.futures import ThreadPoolExecutor
import subprocess
import platform
import ssl
import urllib.request
import urllib.parse
import re
import ipaddress

class NetworkScanner:
    """Advanced Network Security Scanner for authorized security assessments."""
    def __init__(self, target, ports=None, timeout=1):
        self.target = target
        self.ports = ports if ports else list(range(1, 1025))
        self.timeout = timeout
        self.open_ports = []
        self.services = {}
        self.vulnerabilities = []
        self.banners = {}
        self.os_info = {}
        self.ssl_info = {}

    def scan_port(self, port):
        """Scan a single port and grab banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                self.open_ports.append(port)
                service = self.detect_service(port)
                self.services[port] = service

                # Grab banner for detailed service identification
                banner = self.grab_banner(sock, port)
                if banner:
                    self.banners[port] = banner
                    service = self.identify_service_from_banner(banner, port)
                    self.services[port] = service

                sock.close()
                return port, True, service
            else:
                sock.close()
        except (ConnectionError, socket.timeout, OSError):
            pass
        return port, False, None

    def grab_banner(self, sock, port):
        """Grab service banner from open port"""
        try:
            # Send appropriate probe based on port
            probes = {
                21: b'\r\n',
                22: b'\r\n',
                23: b'\r\n',
                25: b'EHLO test\r\n',
                80: b'GET / HTTP/1.1\r\nHost: ' + self.target.encode() + b'\r\n\r\n',
                110: b'USER test\r\n',
                143: b'A001 CAPABILITY\r\n',
                443: b'\r\n',
                3306: b'',
                5432: b'',
                6379: b'INFO\r\n',
                8080: b'GET / HTTP/1.1\r\nHost: ' + self.target.encode() + b'\r\n\r\n'
            }

            if port in probes:
                sock.send(probes[port])

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200]  # Limit banner length
        except (ConnectionError, socket.timeout, OSError):
            return None

    def identify_service_from_banner(self, banner, port):
        """Identify service from banner content"""
        banner_lower = banner.lower()

        # Web servers
        if 'apache' in banner_lower:
            return 'Apache HTTP'
        elif 'nginx' in banner_lower:
            return 'Nginx HTTP'
        elif 'iis' in banner_lower:
            return 'IIS HTTP'

        # SSH
        if 'ssh' in banner_lower or port == 22:
            return 'SSH'

        # FTP
        if 'ftp' in banner_lower or port == 21:
            return 'FTP'

        # SMTP
        if 'smtp' in banner_lower or 'esmtp' in banner_lower or port == 25:
            return 'SMTP'

        # Database
        if 'mysql' in banner_lower:
            return 'MySQL'
        elif 'postgresql' in banner_lower:
            return 'PostgreSQL'
        elif 'redis' in banner_lower:
            return 'Redis'

        return self.detect_service(port)

    def detect_service(self, port):
        """Detect service running on a port"""
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        return common_services.get(port, "Unknown")

    def scan_ports(self, max_threads=50):
        """Scan multiple ports using threading"""
        print(f"[*] Starting scan on {self.target}")
        print(f"[*] Scanning {len(self.ports)} ports...")
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            _ = list(executor.map(self.scan_port, self.ports))

        end_time = time.time()
        print(f"[*] Scan completed in {end_time - start_time:.2f} seconds")

        return self.open_ports

    def check_vulnerabilities(self):
        """Advanced vulnerability assessment"""
        # Basic port-based vulnerabilities
        vuln_checks = {
            21: "FTP - Check for anonymous access",
            22: "SSH - Check for weak credentials",
            23: "Telnet - Unencrypted protocol",
            25: "SMTP - Check for open relay",
            53: "DNS - Check for zone transfer",
            80: "HTTP - Check for web vulnerabilities",
            110: "POP3 - Check for authentication bypass",
            143: "IMAP - Check for authentication bypass",
            443: "HTTPS - Check SSL/TLS configuration",
            3389: "RDP - Check for brute force protection",
            3306: "MySQL - Check for default credentials",
            5432: "PostgreSQL - Check for default credentials",
            6379: "Redis - Check for unauthorized access"
        }

        for port in self.open_ports:
            if port in vuln_checks:
                self.vulnerabilities.append({
                    'port': port,
                    'service': self.services.get(port, 'Unknown'),
                    'issue': vuln_checks[port],
                    'severity': self.get_severity(port)
                })

        # Banner-based vulnerability detection
        for port, banner in self.banners.items():
            self.check_banner_vulnerabilities(port, banner)

        # SSL/TLS analysis
        if 443 in self.open_ports or 8443 in self.open_ports:
            self.analyze_ssl_tls()

        # Web vulnerability scanning
        if 80 in self.open_ports or 443 in self.open_ports or 8080 in self.open_ports:
            self.scan_web_vulnerabilities()

    def check_banner_vulnerabilities(self, port, banner):
        """Check banner for known vulnerabilities"""
        banner_lower = banner.lower()

        # Check for outdated software versions
        vulnerable_patterns = {
            r'apache/2\.2\.': 'Apache 2.2.x - Multiple vulnerabilities',
            r'apache/2\.4\.([0-9]{1,2})\.': 'Apache 2.4.x - Check for specific CVEs',
            r'nginx/1\.[0-9]{1,2}\.': 'Old Nginx version - Potential vulnerabilities',
            r'openssh_[0-6]\.': 'Old OpenSSH version - Security issues',
            r'mysql[ -][0-4]\.': 'Old MySQL version - Security vulnerabilities',
            r'postgresql[ -][89]\.': 'Old PostgreSQL version - Security issues'
        }

        for pattern, issue in vulnerable_patterns.items():
            if re.search(pattern, banner_lower):
                self.vulnerabilities.append({
                    'port': port,
                    'service': self.services.get(port, 'Unknown'),
                    'issue': f'Version detection: {issue}',
                    'severity': 'HIGH',
                    'banner': banner[:100]
                })

    def analyze_ssl_tls(self):
        """Analyze SSL/TLS configuration"""
        ssl_ports = [443, 8443]

        for port in ssl_ports:
            if port in self.open_ports:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    with socket.create_connection((self.target, port),
                                                timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                            cert = ssock.getpeercert()
                            version = ssock.version()
                            cipher = ssock.cipher()

                            self.ssl_info[port] = {
                                'version': version,
                                'cipher': cipher,
                                'cert_subject': cert.get('subject'),
                                'cert_issuer': cert.get('issuer'),
                                'cert_version': cert.get('version')
                            }

                            # Check for weak SSL/TLS
                            if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                                self.vulnerabilities.append({
                                    'port': port,
                                    'service': 'HTTPS',
                                    'issue': f'Weak SSL/TLS version: {version}',
                                    'severity': 'HIGH'
                                })

                            # Check for weak ciphers
                            weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
                            if cipher and any(weak in cipher[0].upper()
                                           for weak in weak_ciphers):
                                self.vulnerabilities.append({
                                    'port': port,
                                    'service': 'HTTPS',
                                    'issue': f'Weak cipher suite: {cipher[0]}',
                                    'severity': 'MEDIUM'
                                })

                except (ssl.SSLError, ConnectionError, socket.timeout, OSError) as e:
                    self.vulnerabilities.append({
                        'port': port,
                        'service': 'HTTPS',
                        'issue': f'SSL/TLS analysis failed: {str(e)}',
                        'severity': 'LOW'
                    })

    def scan_web_vulnerabilities(self):
        """Basic web vulnerability scanning"""
        web_ports = [80, 443, 8080, 8443]

        for port in web_ports:
            if port in self.open_ports:
                try:
                    protocol = 'https' if port in [443, 8443] else 'http'
                    base_url = f'{protocol}://{self.target}:{port}'

                    # Check for common vulnerabilities
                    self.check_common_web_vulns(base_url, port)

                except (ConnectionError, socket.timeout, OSError):
                    pass

    def check_common_web_vulns(self, base_url, port):
        """Check for common web vulnerabilities"""
        common_paths = [
            '/admin', '/admin/login', '/phpmyadmin', '/.git/config',
            '/robots.txt', '/.env', '/config.php', '/web.config'
        ]

        for path in common_paths:
            try:
                url = base_url + path
                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'SecurityScanner/1.0')

                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    if response.status == 200:
                        self.vulnerabilities.append({
                            'port': port,
                            'service': 'HTTP/HTTPS',
                            'issue': f'Exposed sensitive path: {path}',
                            'severity': 'MEDIUM' if 'admin' in path else 'LOW'
                        })
            except (ConnectionError, socket.timeout, OSError):
                continue

    def fingerprint_os(self):
        """Basic OS fingerprinting based on open ports and services"""
        # Simple heuristics based on common port patterns
        if 135 in self.open_ports and 139 in self.open_ports and 445 in self.open_ports:
            self.os_info['likely_os'] = 'Windows'
            self.os_info['confidence'] = 'High'
        elif 22 in self.open_ports and 111 in self.open_ports:
            self.os_info['likely_os'] = 'Linux/Unix'
            self.os_info['confidence'] = 'Medium'
        elif 80 in self.open_ports and 443 in self.open_ports and 22 in self.open_ports:
            self.os_info['likely_os'] = 'Linux Server'
            self.os_info['confidence'] = 'Medium'
        else:
            self.os_info['likely_os'] = 'Unknown'
            self.os_info['confidence'] = 'Low'

    def scan_subnet(self, subnet, _ports=None):
        """Scan entire subnet for live hosts"""
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
            live_hosts = []

            print(f"[*] Scanning subnet {subnet}...")

            for ip in network.hosts():
                ip_str = str(ip)
                if self.ping_host_simple(ip_str):
                    live_hosts.append(ip_str)
                    print(f"[+] Host {ip_str} is online")

            return live_hosts
        except (subprocess.SubprocessError, OSError) as e:
            print(f"[!] Subnet scan error: {e}")
            return []

    def ping_host_simple(self, host):
        """Simple ping check for subnet scanning"""
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "500", host]
            else:
                cmd = ["ping", "-c", "1", "-W", "0.5", host]

            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            return result.returncode == 0
        except (ConnectionError, socket.timeout, OSError):
            return False

    def get_severity(self, port):
        """Assign severity level based on port"""
        high_risk = [23, 135, 139, 445, 3389, 1433, 3306]
        medium_risk = [21, 25, 53, 80, 110, 143, 443, 993, 995]

        if port in high_risk:
            return "HIGH"
        elif port in medium_risk:
            return "MEDIUM"
        else:
            return "LOW"

    def ping_host(self):
        """Check if host is reachable"""
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", self.target]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", self.target]

            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            return result.returncode == 0
        except (ConnectionError, socket.timeout, OSError):
            return False

    def generate_report(self):
        """Generate comprehensive scan report"""
        report = {
            'target': self.target,
            'scan_time': datetime.now().isoformat(),
            'open_ports': len(self.open_ports),
            'services': self.services,
            'banners': self.banners,
            'vulnerabilities': self.vulnerabilities,
            'ssl_info': self.ssl_info,
            'os_info': self.os_info,
            'total_ports_scanned': len(self.ports)
        }
        return report

    def print_results(self):
        """Display comprehensive scan results"""
        print("\n" + "="*60)
        print(f"ADVANCED SECURITY SCAN RESULTS FOR {self.target}")
        print("="*60)

        if not self.open_ports:
            print("[+] No open ports found")
            return

        # OS Information
        if self.os_info:
            print("\n[+] OS Fingerprinting:")
            print(f"    Likely OS: {self.os_info.get('likely_os', 'Unknown')}")
            print(f"    Confidence: {self.os_info.get('confidence', 'Low')}")

        print(f"\n[+] Found {len(self.open_ports)} open ports:")
        print("-" * 70)
        print(f"{'Port':<8}{'Service':<20}{'Banner':<30}{'Status':<10}")
        print("-" * 70)

        for port in sorted(self.open_ports):
            service = self.services.get(port, "Unknown")
            banner = (self.banners.get(port, "")[:25] + "...") if self.banners.get(port) else "N/A"
            print(f"{port:<8}{service:<20}{banner:<30}{'OPEN':<10}")

        # SSL/TLS Information
        if self.ssl_info:
            print("\n[+] SSL/TLS Analysis:")
            for port, info in self.ssl_info.items():
                print(f"    Port {port}: {info['version']}, Cipher: {info['cipher'][0] if info['cipher'] else 'Unknown'}")

        # Vulnerabilities
        if self.vulnerabilities:
            print("\n[!] Security Issues Found:")
            print("-" * 80)
            print(f"{'Port':<6}{'Service':<15}{'Severity':<10}"
                  f"{'Issue':<40}")
            print("-" * 80)

            for vuln in self.vulnerabilities:
                issue = vuln['issue'][:37] + "..." if len(vuln['issue']) > 37 else vuln['issue']
                print(f"{vuln['port']:<6}{vuln['service']:<15}{vuln['severity']:<10}{issue:<40}")

        # Summary
        high_count = len([v for v in self.vulnerabilities if v['severity'] == 'HIGH'])
        medium_count = len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM'])
        low_count = len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])

        print("\n[+] Security Summary:")
        print(f"    High Risk: {high_count}")
        print(f"    Medium Risk: {medium_count}")
        print(f"    Low Risk: {low_count}")
        print(f"    Total Issues: {len(self.vulnerabilities)}")

def main():
    """Main function to handle command line arguments and execute scanning."""
    parser = argparse.ArgumentParser(
        description="Advanced Ethical Network Security Scanner")
    parser.add_argument("target", nargs='?', 
                       help="Target IP address, hostname, or subnet "
                            "(e.g., 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", 
                       help="Port range (e.g., 1-1000) or comma-separated ports")
    parser.add_argument("-t", "--timeout", type=int, default=1,
                       help="Connection timeout in seconds")
    parser.add_argument("-o", "--output", 
                       help="Save results to JSON file")
    parser.add_argument("--no-ping", action="store_true",
                       help="Skip host ping check")
    parser.add_argument("--subnet-scan", action="store_true",
                       help="Scan entire subnet for live hosts")
    parser.add_argument("--max-threads", type=int, default=50,
                       help="Maximum threads for scanning")
    parser.add_argument("--banner-grab", action="store_true", default=True,
                       help="Enable banner grabbing")
    parser.add_argument("--ssl-check", action="store_true", default=True,
                       help="Enable SSL/TLS analysis")
    parser.add_argument("--web-scan", action="store_true", default=True,
                       help="Enable web vulnerability scanning")

    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        print("\n[!] Error: Target is required")
        sys.exit(1)

    # Parse ports
    if args.ports:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p.strip()) for p in args.ports.split(',')]
    else:
        ports = list(range(1, 1025))

    # Subnet scanning mode
    if args.subnet_scan:
        scanner = NetworkScanner("dummy", ports, args.timeout)
        live_hosts = scanner.scan_subnet(args.target, ports)

        if not live_hosts:
            print("[!] No live hosts found in subnet")
            sys.exit(0)

        print(f"\n[*] Found {len(live_hosts)} live hosts. Starting detailed scans...")

        all_results = []
        for host in live_hosts[:10]:  # Limit to first 10 hosts to avoid excessive scanning
            print(f"\n[*] Scanning host: {host}")
            host_scanner = NetworkScanner(host, ports, args.timeout)

            if not args.no_ping and not host_scanner.ping_host():
                continue

            host_scanner.scan_ports(args.max_threads)
            host_scanner.check_vulnerabilities()
            host_scanner.fingerprint_os()
            host_scanner.print_results()

            all_results.append(host_scanner.generate_report())

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(all_results, f, indent=2)
            print(f"\n[*] All results saved to {args.output}")

        print("\n[!] Remember: Only scan networks and systems you have permission to test!")
        print("[!] Unauthorized scanning is illegal and unethical.")
        sys.exit(0)

    # Single host scanning
    scanner = NetworkScanner(args.target, ports, args.timeout)

    # Check if host is reachable
    if not args.no_ping:
        print(f"[*] Checking if {args.target} is reachable...")
        if not scanner.ping_host():
            print(f"[!] Host {args.target} appears to be down or blocking pings")
            response = input("Continue anyway? (y/n): ")
            if response.lower() != 'y':
                sys.exit(1)

    # Perform advanced scan
    scanner.scan_ports(args.max_threads)
    scanner.fingerprint_os()
    scanner.check_vulnerabilities()
    scanner.print_results()

    # Save results if requested
    if args.output:
        report = scanner.generate_report()
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        print(f"\n[*] Results saved to {args.output}")

    print("\n[!] Remember: Only scan networks and systems you have permission to test!")
    print("[!] Unauthorized scanning is illegal and unethical.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except (ValueError, OSError, KeyboardInterrupt) as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
