# CyberSec Toolkit 2025 - Enhanced Edition

![CyberSec Toolkit Banner](https://via.placeholder.com/800x200.png?text=CyberSec+Toolkit+2025)  
*Submission for Project Competition 2025 by ThinkCyber*

---

## Project Overview



The **CyberSec Toolkit 2025 - Enhanced Edition** is a sophisticated Python-based cybersecurity suite designed for the ThinkCyber Project Competition 2025. It integrates five powerful tools with advanced features, showcasing technical expertise, creativity, and practical application in a user-friendly package. Built for educational and authorized use, this toolkit empowers users to monitor systems, test security, gather intelligence, scan networks, and analyze logs with cutting-edge enhancements.

### Core Features
1. **System Metrics Monitoring**: Real-time system stats with anomaly detection.
2. **Security Testing**: Simulated attacks using packet crafting.
3. **Remote Reconnaissance**: SSH-based intel with encrypted credentials.
4. **Network Scanning**: Detailed scanning with vulnerability scoring and visualization.
5. **Auth Log Analyzer**: Log analysis with threat intelligence integration.

### Advanced Enhancements
- **Anomaly Detection**: Flags unusual CPU usage via statistical analysis.
- **Packet Crafting**: Simulates SYN floods with Scapy for educational demos.
- **Credential Encryption**: Secures SSH credentials using Fernet.
- **Vulnerability Scoring**: Custom CVSS-like scoring for risk assessment.
- **Network Visualization**: Bar charts of vulnerability scores with Matplotlib.
- **Threat Intelligence**: VirusTotal API lookup for suspicious IPs.

---

## Technical Specifications

- **Language**: Python 3.8+
- **Dependencies**:
  - System Tools: `nmap`, `masscan`, `hydra`, `hping3`, `whois`
  - Python Libraries: `rich`, `paramiko`, `cryptography`, `scapy`, `matplotlib`, `requests`
- **Platform**: Linux (Ubuntu recommended)
- **Privileges**: Root access required for network operations

---

## Installation

### Prerequisites
- Linux system (e.g., Ubuntu 20.04+)
- Python 3.8+
- Root or sudo access

### Steps

1. **Obtain the Project**  
   Clone the repository if hosted:
   ```bash
   git clone https://github.com/humuraelvin/Quantum-Lock.git
   cd cybersec-toolkit-2025

2.

sudo apt-get update
sudo apt-get install -y nmap masscan hydra hping3 whois

3.

pip install rich paramiko cryptography scapy matplotlib requests selenium beautifulsoup4 pyshark yara-python python-magic pefile volatility3 r2pipe

4. 

chmod +x cybersec_toolkit.py

5.

sudo ./cybersec_toolkit.py