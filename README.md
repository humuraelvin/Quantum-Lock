# CyberSec Toolkit 2025 - Enhanced Edition

![CyberSec Toolkit Banner](https://via.placeholder.com/800x200.png?text=CyberSec+Toolkit+2025)  
*Submission for Project Competition 2025 by ThinkCyber*

---

## Project Overview

**Author**: ELVIN HUMURA  
**Student Code**: S24  
**Class Code**: RW-CODING-ACADEMY-I  
**Lecturer**: CELESTIN NZEYIMANA  
**Institution**: Rwanda Coding Academy

The **CyberSec Toolkit 2025 - Enhanced Edition** is a sophisticated Python-based cybersecurity suite designed for the ThinkCyber Project Competition 2025. It integrates twenty-five powerful tools with advanced features, showcasing technical expertise, creativity, and practical application in a user-friendly terminal-based interface. Built for educational and authorized use, this toolkit empowers users with comprehensive system monitoring, security testing, network analysis, forensics capabilities, and advanced threat intelligence features.

### Core Features

1. **System Metrics Monitoring**: Real-time system stats with anomaly detection
2. **Security Testing**: Simulated attacks using packet crafting
3. **Remote Reconnaissance**: SSH-based intel with encrypted credentials
4. **Network Scanning**: Detailed scanning with vulnerability scoring
5. **Auth Log Analyzer**: Log analysis with threat intelligence integration
6. **DNS Enumeration**: DNS record analysis with spoofing detection
7. **Firewall Rule Auditor**: Analyze and optimize firewall configurations
8. **Wi-Fi Security Scanner**: Wireless network assessment and analysis
9. **Intrusion Detection**: Real-time packet monitoring and threat detection
10. **DDoS Mitigation**: Attack simulation and defense strategy testing
11. **Protocol Analyzer**: Deep packet inspection and traffic analysis
12. **Malware Analysis Lab**: Static and dynamic malware investigation
13. **Web Security Scanner**: Automated vulnerability assessment
14. **Memory Forensics**: RAM dump analysis and process inspection
15. **Binary Analysis**: Reverse engineering and binary inspection
16. **OSINT Collection**: Automated web, WHOIS, and Shodan intelligence gathering
17. **SSL/TLS Auditor**: Certificate and cipher suite security analysis
18. **Phishing Detection**: Email and URL phishing analysis
19. **Dark Web Scanner**: Onion network search capabilities
20. **Exploit Framework**: Automated vulnerability exploitation
21. **Synthetic Attack Generator**: Multi-vector attack simulation
22. **Advanced Packet Forensics**: Deep PCAP analysis
23. **GeoIP Threat Mapping**: Location-based threat intelligence
24. **SOC Automation**: Real-time security operations center dashboard
25. **Honeypot Deployment**: Automated attacker trap system

### Advanced Capabilities

#### Network Security
- **Deep Packet Inspection**: Protocol-level traffic analysis
- **Packet Crafting**: Advanced packet manipulation with Scapy
- **Network Visualization**: Traffic patterns and protocol distribution
- **Vulnerability Scoring**: Custom CVSS-like risk assessment
- **SSL/TLS Analysis**: Certificate validation and cipher suite assessment
- **Dark Web Monitoring**: Tor network intelligence gathering

#### System Security
- **Anomaly Detection**: Statistical analysis of system metrics
- **Process Monitoring**: Real-time process and resource tracking
- **Firewall Analysis**: Rule auditing and optimization
- **Memory Analysis**: Live system memory inspection
- **Honeypot Operations**: Attacker behavior analysis
- **SOC Dashboard**: Real-time security monitoring

#### Threat Intelligence
- **OSINT Collection**: Automated intelligence gathering
- **GeoIP Mapping**: Geographic threat visualization
- **Phishing Analysis**: Email and URL threat detection
- **Dark Web Intelligence**: Hidden service monitoring
- **Threat Database**: SQLite-based threat tracking
- **Real-time Alerts**: Immediate threat notification

#### Malware Analysis
- **Static Analysis**: File signatures and pattern matching
- **PE File Analysis**: Windows executable inspection
- **YARA Rules**: Custom malware pattern detection
- **String Analysis**: Embedded text and pattern extraction
- **Memory Forensics**: Process and DLL inspection
- **Behavioral Analysis**: Dynamic execution monitoring

#### Web Security
- **XSS Detection**: Cross-site scripting vulnerability testing
- **SQL Injection**: Database attack simulation
- **Directory Traversal**: Path manipulation testing
- **Automated Scanning**: Headless browser-based testing
- **SSL Certificate Analysis**: Trust chain validation
- **Web Application Fuzzing**: Input validation testing

#### Forensics & Analysis
- **Memory Forensics**: RAM dump analysis with Volatility3
- **Binary Analysis**: Reverse engineering with Radare2
- **Network Forensics**: Traffic capture and analysis
- **Log Analysis**: System and security log inspection
- **PCAP Analysis**: Deep packet inspection
- **Threat Attribution**: GeoIP-based source tracking

#### Reporting & Visualization
- **PDF Reports**: Automated report generation
- **Data Visualization**: Interactive charts and graphs
- **Terminal UI**: Rich console-based interface
- **Detailed Logging**: Comprehensive activity tracking
- **Threat Maps**: Geographic visualization
- **Real-time Dashboards**: Live security monitoring

---

## Technical Specifications

### System Requirements
- **OS**: Linux (Ubuntu 20.04+) or Windows 10/11
- **Python**: 3.8 or higher
- **Privileges**: Administrator/Root access required
- **Memory**: 8GB RAM minimum (16GB+ recommended)
- **Storage**: 2GB free space for tools and databases
- **Network**: Stable internet connection required

### Dependencies

#### System Tools
```bash
# Network Tools
nmap            # Network scanning
masscan         # Mass IP port scanning
hydra           # Password attacks
hping3          # Network packet crafting
whois           # Domain information lookup
aircrack-ng     # Wireless network analysis
tcpdump         # Packet capture
wireshark       # Packet analysis

# Analysis Tools
radare2         # Binary analysis
volatility      # Memory forensics
tesseract-ocr   # OCR capabilities
tor             # Dark web access

# Development Tools
git             # Version control
build-essential # Compilation tools
python3-dev     # Python development
```

#### Python Libraries
```python
# Core Dependencies
rich>=10.0.0           # Terminal UI
paramiko>=2.7.2        # SSH operations
cryptography>=3.4.7    # Encryption
scapy>=2.4.5          # Packet manipulation
matplotlib>=3.4.2      # Data visualization
requests>=2.25.1       # HTTP operations
aiohttp>=3.8.0        # Async HTTP
asyncio>=3.4.3        # Async operations

# Security Tools
selenium>=4.0.0        # Web automation
beautifulsoup4>=4.9.3  # HTML parsing
pyshark>=0.4.2.11     # Packet analysis
yara-python>=4.1.0    # Malware detection
python-magic>=0.4.24  # File type detection
pefile>=2021.5.24     # PE file analysis
volatility3>=2.0.0    # Memory forensics
r2pipe>=1.6.3         # Radare2 integration

# Additional Features
python-whois>=0.7.3   # WHOIS lookups
pyOpenSSL>=20.0.1     # SSL analysis
opencv-python>=4.5.3  # Image processing
pytesseract>=0.3.8    # OCR support
faker>=8.1.2          # Data generation
virustotal-python>=0.1.0  # VirusTotal API
pygeoip>=0.3.2        # GeoIP lookup
maxminddb>=2.0.3      # GeoIP database
dnspython>=2.1.0      # DNS operations
```

---

## Installation

### Prerequisites
1. Ensure your system meets the minimum requirements
2. Install Python 3.8 or higher
3. Install git for repository management
4. Have administrator/root access

### Step-by-Step Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/humuraelvin/Quantum-Lock.git
   cd Quantum-Lock
   ```

2. **Install System Dependencies (Ubuntu/Debian)**
   ```bash
   sudo apt-get update
   sudo apt-get install -y nmap masscan hydra hping3 whois aircrack-ng tcpdump wireshark radare2 volatility tesseract-ocr tor git build-essential python3-dev python3-pip
   ```

   **For Windows:**
   - Install tools manually from their respective websites
   - Use Windows Subsystem for Linux (WSL) for Linux-specific tools

3. **Create and Activate Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   .\venv\Scripts\activate  # Windows
   ```

4. **Install Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Download Additional Resources**
   ```bash
   # Download GeoIP database
   wget https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz -O GeoLite2-City.tar.gz
   tar -xzf GeoLite2-City.tar.gz
   ```

6. **Set Execution Permissions (Linux/Mac)**
   ```bash
   chmod +x QuantumLockScript.py
   ```

7. **Initialize the Environment**
   ```bash
   python QuantumLockScript.py --init
   ```

---

## Usage

1. **Launch the Toolkit**
   ```bash
   sudo ./QuantumLockScript.py  # Linux/Mac
   # or
   python QuantumLockScript.py  # Windows (as Administrator)
   ```

2. **Navigate the Menu**
   - Use number keys (0-25) to select tools
   - Follow on-screen prompts
   - Use Ctrl+C to exit current tool
   - Select '0' to exit properly

3. **View Results**
   - Check the `cybersec_output_YYYYMMDD_HHMMSS` directory
   - Review generated PDF reports
   - Analyze logs in the output directory

4. **Database Management**
   - Threat data is stored in SQLite database
   - Use built-in tools to query and analyze
   - Regular backups recommended

---

## Security Notice

This toolkit is designed for educational and authorized testing purposes only. Ensure you have proper authorization before testing any systems or networks. Unauthorized use against systems without explicit permission is illegal and unethical.

Features like the Dark Web Scanner, Exploit Framework, and Attack Generator should be used with extreme caution and only in controlled environments.

---

## License

Copyright © 2025 ELVIN HUMURA. All rights reserved.

This software is provided for educational purposes only. Any unauthorized use, reproduction, or distribution is strictly prohibited.