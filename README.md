Advanced Ethical Network Security Scanner
A comprehensive Python-based network security scanner for authorized security assessments with advanced vulnerability detection capabilities.

🚀 New Advanced Features
Banner Grabbing
Automatic service banner extraction
Detailed service version identification
Vulnerability detection based on software versions
SSL/TLS Analysis
Certificate information extraction
Weak protocol version detection
Cipher suite analysis
Security configuration assessment
Web Vulnerability Scanning
Common sensitive path detection
Admin panel discovery
Configuration file exposure checks
OS Fingerprinting
Operating system detection
Confidence level assessment
Based on open port patterns
Subnet Scanning
Network discovery capabilities
Multiple host scanning
Live host identification
Features
🔍 Port Scanning: Fast multi-threaded port scanning
🎯 Service Detection: Identifies common services with banner analysis
🛡️ Vulnerability Assessment: Advanced security checks with CVE detection
🌐 Host Discovery: Ping check and subnet scanning
📊 Report Generation: Comprehensive JSON export
🔒 SSL/TLS Analysis: Certificate and cipher analysis
🖥️ OS Detection: Operating system fingerprinting
🌍 Web Scanning: Basic web vulnerability assessment
Usage
Basic Scan
python network_scanner_fixed.py 192.168.1.1
Advanced Scan with All Features
python network_scanner_fixed.py 192.168.1.1 -p 1-1000 -o advanced_scan.json
Subnet Scanning
python network_scanner_fixed.py 192.168.1.0/24 --subnet-scan
Custom Port Range
python network_scanner_fixed.py 192.168.1.1 -p 1-1000
Specific Ports
python network_scanner_fixed.py 192.168.1.1 -p 22,80,443,3389
Save Results
python network_scanner_fixed.py 192.168.1.1 -o scan_results.json
Skip Ping Check
python network_scanner_fixed.py 192.168.1.1 --no-ping
Advanced Options
target: Target IP address, hostname, or subnet (required)
-p, --ports: Port range (1-1000) or comma-separated ports
-t, --timeout: Connection timeout in seconds (default: 1)
-o, --output: Save results to JSON file
--no-ping: Skip host reachability check
--subnet-scan: Scan entire subnet for live hosts
--max-threads: Maximum threads for scanning (default: 50)
--banner-grab: Enable banner grabbing (default: True)
--ssl-check: Enable SSL/TLS analysis (default: True)
--web-scan: Enable web vulnerability scanning (default: True)
Examples
Scan Your Local Network
# Scan your router with all features
python network_scanner_fixed.py 192.168.1.1 -o router_scan.json

# Scan entire subnet
python network_scanner_fixed.py 192.168.1.0/24 --subnet-scan -o network_scan.json
Web Server Security Assessment
python network_scanner_fixed.py example.com -p 80,443,8080,8443 -o web_security.json
Internal Network Security Audit
python network_scanner_fixed.py 10.0.0.1 -p 22,23,53,80,135,139,443,445,3389 -o internal_audit.json
Fast Port Scan
python network_scanner_fixed.py 192.168.1.100 -p 1-1000 --max-threads 100
Output
The advanced scanner provides:

Open ports with detailed service information
Service banners for version detection
OS fingerprinting with confidence levels
SSL/TLS analysis with certificate details
Web vulnerabilities and exposed paths
Security issues with severity classification
Comprehensive JSON report (if requested)
Security Levels
🔴 HIGH: Telnet, RDP, SMB, Database services, Weak SSL/TLS
🟡 MEDIUM: HTTP, HTTPS, FTP, SSH, Email services
🟢 LOW: Other services and informational issues
Advanced Vulnerability Detection
Version-Based Detection
Apache 2.2.x vulnerabilities
Old Nginx versions
Outdated OpenSSH
Legacy MySQL/PostgreSQL
Weak SSL/TLS protocols
Service-Based Detection
Anonymous FTP access
Open SMTP relay
DNS zone transfer
Default database credentials
Exposed admin panels
Web Vulnerabilities
/admin panel exposure
/phpmyadmin access
Configuration file leaks
.git repository exposure
Sensitive file discovery
Sample Advanced Output
[*] Starting scan on 192.168.1.1
[*] Scanning 1024 ports...
[*] Scan completed in 2.34 seconds

============================================================
ADVANCED SECURITY SCAN RESULTS FOR 192.168.1.1
============================================================

[+] OS Fingerprinting:
    Likely OS: Windows
    Confidence: High

[+] Found 5 open ports:
----------------------------------------------------------------------
Port    Service              Banner                       Status    
----------------------------------------------------------------------
22      SSH                 OpenSSH_7.4p1...             OPEN       
80      HTTP                Apache/2.4.29...             OPEN       
443     HTTPS               Apache/2.4.29...             OPEN       
3306    MySQL               MySQL 5.7.25...              OPEN       
3389    RDP                 N/A                          OPEN       

[+] SSL/TLS Analysis:
    Port 443: TLSv1.2, Cipher: ECDHE-RSA-AES256-GCM-SHA384

[!] Security Issues Found:
--------------------------------------------------------------------------------
Port  Service       Severity  Issue                                       
--------------------------------------------------------------------------------
23    Telnet        HIGH      Telnet - Unencrypted protocol               
80    HTTP          MEDIUM    Version detection: Apache 2.4.29 - Check for specific CVEs
443   HTTPS         MEDIUM    Exposed sensitive path: /admin              
3306  MySQL         HIGH      MySQL - Check for default credentials       
3389  RDP           HIGH      RDP - Check for brute force protection      

[+] Security Summary:
    High Risk: 3
    Medium Risk: 2
    Low Risk: 0
    Total Issues: 5

[*] Results saved to advanced_scan.json

[!] Remember: Only scan networks and systems you have permission to test!
[!] Unauthorized scanning is illegal and unethical.
Legal & Ethical Notice
⚠️ IMPORTANT: Only scan networks and systems you have explicit permission to test.

Unauthorized scanning is illegal in most jurisdictions
Always get written permission before security testing
Use only for legitimate security purposes
Respect privacy and network policies
This tool includes advanced features - use responsibly
Requirements
Python 3.6+
Standard library only (no external dependencies)
Network access for scanning
Administrative privileges for privileged ports (< 1024)
Installation
# Download the advanced scanner
# Make it executable (Linux/Mac)
chmod +x network_scanner_fixed.py

# Run with help to see all options
python network_scanner_fixed.py --help
Advanced Usage Scenarios
Corporate Network Assessment
# Scan entire corporate subnet
python network_scanner_fixed.py 10.0.0.0/24 --subnet-scan -o corporate_audit.json --max-threads 100

# Detailed web server analysis
python network_scanner_fixed.py web-server.company.com -p 1-65535 -o web_server_analysis.json
Penetration Testing
# Quick recon scan
python network_scanner_fixed.py target.com -p 21,22,23,25,53,80,110,143,443,993,995,3389

# Comprehensive assessment
python network_scanner_fixed.py target.com -p 1-1000 --max-threads 200 -o full_assessment.json
Security Monitoring
# Regular security check
python network_scanner_fixed.py 192.168.1.1 -o daily_scan_$(date +%Y%m%d).json

# Network discovery
python network_scanner_fixed.py 192.168.0.0/16 --subnet-scan -o network_inventory.json
Troubleshooting
Permission Denied
Run with appropriate privileges for privileged ports
On Linux/Mac: sudo python network_scanner_fixed.py target
Host Unreachable
Check network connectivity
Use --no-ping flag if ICMP is blocked
Verify target IP/hostname
Slow Scanning
Reduce port range with -p option
Increase timeout with -t option
Adjust thread count with --max-threads
SSL/TLS Issues
Check if target supports SSL/TLS
Verify firewall isn't blocking port 443
Use --no-ssl-check to disable if needed
API Integration
Python Integration
from network_scanner_fixed import NetworkScanner

# Create scanner instance
scanner = NetworkScanner("192.168.1.1", [22, 80, 443])

# Perform comprehensive scan
scanner.scan_ports()
scanner.fingerprint_os()
scanner.check_vulnerabilities()

# Get detailed results
results = scanner.generate_report()
print(f"Found {len(results['vulnerabilities'])} security issues")
Batch Processing
# Scan multiple targets from file
for target in $(cat targets.txt); do
    python network_scanner_fixed.py $target -o "scan_$target.json"
done
Contributing
This advanced scanner includes cutting-edge security features. Contributions welcome for:

Additional vulnerability checks
New service signatures
Enhanced OS detection
Web vulnerability modules
Performance optimizations
Remember: All contributions must maintain ethical security standards.
