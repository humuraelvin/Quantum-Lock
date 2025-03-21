#!/usr/bin/env python3

"""
Project: CyberSec Toolkit 2025 - Enhanced Edition
Author: ELVIN HUMURA
Student Code: S24
Class Code: RW-CODING-ACADEMY-I
Lecturer: CELESTIN NZEYIMANA
Submission Date: March 21, 2025
Competition: Project Competition 2025 by ThinkCyber
Institution: Rwanda Coding Academy

Description:
This advanced cybersecurity toolkit integrates five core tools with additional genius features:
system monitoring with anomaly detection, network scanning with vulnerability scoring,
remote reconnaissance via SSH, simulated attacks with packet crafting, and log analysis with
threat visualization. It leverages external libraries for a professional interface and robust
functionality, designed for authorized educational use.

Genius Concepts Added:
- Real-time anomaly detection in system monitoring using statistical thresholds.
- Encrypted credential storage for SSH using Fernet.
- Custom vulnerability scoring based on CVSS-like metrics.
- Packet crafting for simulated attacks with Scapy.
- Network visualization with Matplotlib for scan results.
- Threat intelligence lookup using an external API (e.g., VirusTotal).
"""

import os
import sys
import re
import time
import subprocess
import threading
from datetime import datetime
from collections import Counter, defaultdict
import logging
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
import paramiko
import socket
import statistics
from cryptography.fernet import Fernet
import json
import requests
from scapy.all import IP, TCP, send  # Requires scapy: pip install scapy
import matplotlib.pyplot as plt  # Requires matplotlib: pip install matplotlib

# Initialize console for rich output
console = Console()

# Setup logging
OUTPUT_DIR = f"cybersec_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(OUTPUT_DIR, exist_ok=True)
LOG_FILE = os.path.join(OUTPUT_DIR, "cybersec_toolkit.log")
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger()

# Encryption for credential storage
KEY_FILE = os.path.join(OUTPUT_DIR, "secret.key")
CRED_FILE = os.path.join(OUTPUT_DIR, "credentials.enc")
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
else:
    with open(KEY_FILE, "rb") as f:
        key = f.read()
cipher = Fernet(key)

# Function to display the toolkit banner
def display_banner():
    console.clear()
    console.print("[green]=========================================================[/green]")
    console.print("[cyan]  CyberSec Toolkit 2025 - Enhanced ThinkCyber Edition   [/cyan]")
    console.print("[green]=========================================================[/green]")
    console.print(f"[yellow]Author: [Your Name Here] | Date: March 21, 2025[/yellow]")
    console.print("[yellow]Advanced cybersecurity testing for authorized use only.[/yellow]")
    console.print("[green]=========================================================[/green]")
    console.print()

# Function to check and install dependencies
def check_dependencies():
    dependencies = ["nmap", "masscan", "hydra", "hping3", "whois", "scapy"]
    missing = []
    for dep in dependencies:
        if subprocess.call(["which", dep], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            missing.append(dep)
    if missing:
        console.print(f"[red]Missing system dependencies: {', '.join(missing)}[/red]")
        if Confirm.ask("Install missing dependencies?", default=True):
            subprocess.run(["sudo", "apt-get", "update"])
            subprocess.run(["sudo", "apt-get", "install", "-y"] + missing)
            logger.info(f"Installed system dependencies: {', '.join(missing)}")
    python_deps = ["rich", "paramiko", "cryptography", "matplotlib", "requests"]
    for dep in python_deps:
        if subprocess.call([sys.executable, "-m", "pip", "show", dep], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            subprocess.run([sys.executable, "-m", "pip", "install", dep])
            logger.info(f"Installed Python dependency: {dep}")
    logger.info("Dependencies check completed.")

# Task 1: System Metrics Monitoring with Anomaly Detection
def system_metrics_monitor():
    logger.info("Starting System Metrics Monitor with Anomaly Detection")
    stop_event = threading.Event()
    cpu_history = []
    anomaly_threshold = 2  # Standard deviations above mean

    def detect_anomaly(current_value, history):
        if len(history) < 10:  # Need enough data for meaningful stats
            return False
        mean = statistics.mean(history)
        std = statistics.stdev(history)
        return abs(current_value - mean) > anomaly_threshold * std

    def monitor_thread():
        while not stop_event.is_set():
            console.clear()
            console.print("[cyan]=== SYSTEM METRICS MONITOR ===[/cyan]")
            console.print(f"[yellow]Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")

            # Network Details
            private_ip = socket.gethostbyname(socket.gethostname())
            public_ip = subprocess.check_output(["curl", "-s", "ifconfig.me"]).decode().strip()
            gateway = subprocess.check_output(["ip", "route", "show", "default"]).decode().split()[2]
            console.print(f"[blue]Private IP:[/blue] {private_ip}")
            console.print(f"[blue]Public IP:[/blue] {public_ip}")
            console.print(f"[blue]Gateway:[/blue] {gateway}")

            # CPU Usage with Anomaly Detection
            cpu_usage = float(subprocess.check_output(["top", "-bn1"]).decode().splitlines()[2].split()[1])
            cpu_history.append(cpu_usage)
            if len(cpu_history) > 100:  # Keep history manageable
                cpu_history.pop(0)
            console.print(f"[blue]CPU Usage:[/blue] {cpu_usage}%")
            if detect_anomaly(cpu_usage, cpu_history):
                console.print(f"[red]ALERT: CPU anomaly detected! Usage: {cpu_usage}%[/red]")
                logger.warning(f"CPU anomaly detected: {cpu_usage}%")

            console.print("[yellow]Press Ctrl+C to return to menu...[/yellow]")
            time.sleep(5)

    thread = threading.Thread(target=monitor_thread)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        stop_event.set()
        thread.join()
    console.print("[green]Monitoring stopped.[/green]")

# Task 2: Security Testing with Packet Crafting
def security_testing():
    logger.info("Starting Security Testing Module with Packet Crafting")
    console.print("[cyan]Enter local subnet to scan (e.g., 192.168.1.0/24):[/cyan]")
    subnet = Prompt.ask("Subnet")
    if not re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", subnet):
        console.print("[red]Invalid subnet format.[/red]")
        return

    # Scan network
    console.print("[yellow]Scanning network...[/yellow]")
    result = subprocess.check_output(["nmap", "-sn", subnet]).decode()
    ips = re.findall(r"Nmap scan report for ([\d.]+)", result)
    if not ips:
        console.print("[red]No IPs found.[/red]")
        return

    # Display IPs
    table = Table(title="Available IPs")
    table.add_column("Index", style="green")
    table.add_column("IP", style="yellow")
    for i, ip in enumerate(ips):
        table.add_row(str(i), ip)
    console.print(table)

    choice = Prompt.ask("Select IP index or 'r' for random", default="r")
    target_ip = ips[int(choice)] if choice.isdigit() and int(choice) < len(ips) else ips[0]

    # Simulated SYN flood with Scapy
    console.print(f"[cyan]Simulating SYN flood on {target_ip} (port 80)...[/cyan]")
    console.print("[yellow]Note: Limited to 100 packets for demo purposes.[/yellow]")
    packet = IP(dst=target_ip) / TCP(dport=80, flags="S")
    try:
        send(packet, count=100, verbose=False)
        logger.info(f"SYN flood simulation completed on {target_ip}")
        console.print(f"[green]SYN flood simulation completed on {target_ip}[/green]")
    except PermissionError:
        console.print("[red]Error: Run as root for packet crafting.[/red]")

# Task 3: Remote Reconnaissance with Credential Encryption
def remote_reconnaissance():
    logger.info("Starting Remote Reconnaissance Module")
    console.print("[cyan]Enter remote server IP:[/cyan]")
    server_ip = Prompt.ask("Server IP")
    console.print("[cyan]Enter username:[/cyan]")
    username = Prompt.ask("Username")
    console.print("[cyan]Enter password:[/cyan]")
    password = Prompt.ask("Password", password=True)
    console.print("[cyan]Enter target address to scan:[/cyan]")
    target = Prompt.ask("Target Address")

    # Encrypt and store credentials
    creds = {"username": username, "password": password}
    encrypted_creds = cipher.encrypt(json.dumps(creds).encode())
    with open(CRED_FILE, "wb") as f:
        f.write(encrypted_creds)
    logger.info(f"Credentials encrypted and stored in {CRED_FILE}")

    # SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(server_ip, username=username, password=password)
        console.print("[green]Connected to remote server.[/green]")

        # Whois
        _, stdout, _ = ssh.exec_command(f"whois {target}")
        whois_output = stdout.read().decode()
        whois_file = os.path.join(OUTPUT_DIR, f"whois_{target}.txt")
        with open(whois_file, "w") as f:
            f.write(whois_output)
        logger.info(f"Whois completed for {target}. Saved to {whois_file}")

        # Nmap
        _, stdout, _ = ssh.exec_command(f"nmap -sS -T4 {target}")
        nmap_output = stdout.read().decode()
        nmap_file = os.path.join(OUTPUT_DIR, f"nmap_{target}.txt")
        with open(nmap_file, "w") as f:
            f.write(nmap_output)
        logger.info(f"Nmap scan completed for {target}. Saved to {nmap_file}")

        console.print(f"[green]Reconnaissance completed. Results in {OUTPUT_DIR}[/green]")
    except Exception as e:
        console.print(f"[red]SSH Error: {e}[/red]")
    finally:
        ssh.close()

# Task 4: Network Scanning with Vulnerability Scoring
def network_scanning():
    logger.info("Starting Network Scanning Module with Vulnerability Scoring")
    console.print("[cyan]Enter target range (e.g., 192.168.1.0/24):[/cyan]")
    target_range = Prompt.ask("Target Range")
    if not re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", target_range):
        console.print("[red]Invalid range format.[/red]")
        return

    # Masscan for host discovery
    console.print("[yellow]Discovering hosts...[/yellow]")
    masscan_file = os.path.join(OUTPUT_DIR, "masscan_results.gnmap")
    subprocess.run(["masscan", target_range, "-p", "1-1000", "--rate=1000", "-oG", masscan_file])
    with open(masscan_file) as f:
        hosts = sorted(set(line.split()[1] for line in f if "Host:" in line))
    logger.info(f"Discovered {len(hosts)} hosts in {target_range}")

    # Nmap detailed scan
    console.print("[yellow]Scanning ports and services...[/yellow]")
    nmap_file = os.path.join(OUTPUT_DIR, "nmap_scan.xml")
    subprocess.run(["nmap", "-sS", "-sV", "-A", "-T4", "-oX", nmap_file] + hosts)

    # Custom vulnerability scoring (simplified CVSS-like)
    vuln_scores = {}
    with open(nmap_file) as f:
        nmap_data = f.read()
        for host in hosts:
            open_ports = len(re.findall(rf"{host}.*?portid=\"(\d+)\"", nmap_data))
            services = re.findall(rf"{host}.*?service name=\"(.*?)\"", nmap_data)
            score = min(10, open_ports * 0.5 + (3 if "http" in services else 0))  # Basic scoring
            vuln_scores[host] = score

    # Display scores
    table = Table(title="Vulnerability Scores")
    table.add_column("Host", style="green")
    table.add_column("Score (0-10)", style="yellow")
    for host, score in vuln_scores.items():
        table.add_row(host, f"{score:.1f}")
    console.print(table)

    # Optional visualization
    if Confirm.ask("Generate network visualization?", default=False):
        plt.bar(vuln_scores.keys(), vuln_scores.values())
        plt.xlabel("Hosts")
        plt.ylabel("Vulnerability Score")
        plt.title("Network Vulnerability Overview")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, "network_viz.png"))
        console.print("[green]Visualization saved to network_viz.png[/green]")

    logger.info(f"Network scan completed. Results in {nmap_file}")
    console.print(f"[green]Scanning completed. Results in {nmap_file}[/green]")

# Task 5: Auth Log Analyzer with Threat Intelligence
def auth_log_analyzer():
    logger.info("Starting Auth Log Analyzer with Threat Intelligence")
    console.print("[cyan]Enter path to auth.log:[/cyan]")
    log_file = Prompt.ask("Log File Path")
    if not os.path.isfile(log_file):
        console.print("[red]File not found.[/red]")
        return

    console.print("[cyan]Enter VirusTotal API key (optional, press Enter to skip):[/cyan]")
    vt_api_key = Prompt.ask("API Key", default="")

    failed_logins = defaultdict(list)
    successful_logins = defaultdict(list)
    with open(log_file, "r", errors="replace") as f:
        for line in f:
            if match := re.search(r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\w+) from (\S+)", line):
                ts, user, ip = match.groups()
                failed_logins[user].append((ts, ip))
            elif match := re.search(r"(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\w+) from (\S+)", line):
                ts, user, ip = match.groups()
                successful_logins[user].append((ts, ip))

    # Threat intelligence lookup
    suspicious_ips = set()
    if vt_api_key:
        console.print("[yellow]Checking IPs with VirusTotal...[/yellow]")
        for user, attempts in failed_logins.items():
            for _, ip in attempts:
                try:
                    response = requests.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={"x-apikey": vt_api_key}
                    ).json()
                    if response["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
                        suspicious_ips.add(ip)
                        logger.warning(f"Suspicious IP detected: {ip}")
                except Exception as e:
                    logger.error(f"VT lookup failed for {ip}: {e}")

    # Generate report
    report_file = os.path.join(OUTPUT_DIR, "auth_log_report.txt")
    with open(report_file, "w") as f:
        f.write("=== AUTH LOG REPORT ===\n")
        f.write(f"Failed Attempts: {sum(len(v) for v in failed_logins.values())}\n")
        f.write(f"Successful Logins: {sum(len(v) for v in successful_logins.values())}\n")
        f.write("\nTop 5 Targeted Users:\n")
        for user, count in Counter({u: len(v) for u, v in failed_logins.items()}).most_common(5):
            f.write(f"  - {user}: {count}\n")
        if suspicious_ips:
            f.write("\nSuspicious IPs (VirusTotal):\n")
            for ip in suspicious_ips:
                f.write(f"  - {ip}\n")

    logger.info(f"Auth log analysis completed. Report in {report_file}")
    console.print(f"[green]Analysis completed. Report in {report_file}[/green]")
    with open(report_file) as f:
        console.print(f.read())

# Function to display the main menu
def display_menu():
    console.print("[cyan]Select a Cybersecurity Task:[/cyan]")
    console.print("[green][1] System Metrics Monitoring[/green] - Real-time with anomaly detection")
    console.print("[green][2] Security Testing[/green] - Simulated attacks with packet crafting")
    console.print("[green][3] Remote Reconnaissance[/green] - SSH-based with encrypted creds")
    console.print("[green][4] Network Scanning[/green] - Vulnerability scoring and visualization")
    console.print("[green][5] Auth Log Analyzer[/green] - With threat intelligence lookup")
    console.print("[green][0] Exit[/green] - Quit the toolkit")
    return Prompt.ask("Enter your choice (0-5)", choices=["0", "1", "2", "3", "4", "5"])

# Main execution loop
def main():
    display_banner()
    check_dependencies()
    logger.info("CyberSec Toolkit initialized")
    while True:
        choice = display_menu()
        try:
            if choice == "1":
                system_metrics_monitor()
            elif choice == "2":
                security_testing()
            elif choice == "3":
                remote_reconnaissance()
            elif choice == "4":
                network_scanning()
            elif choice == "5":
                auth_log_analyzer()
            elif choice == "0":
                console.print("[green]Thank you for using CyberSec Toolkit 2025![/green]")
                console.print(f"[yellow]Logs and results saved to: {OUTPUT_DIR}[/yellow]")
                logger.info("Exiting toolkit")
                sys.exit(0)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            logger.error(f"Task failed: {e}")
        if Confirm.ask("Return to menu?", default=True):
            continue
        else:
            console.print("[green]Exiting...[/green]")
            break

if __name__ == "__main__":
    main()