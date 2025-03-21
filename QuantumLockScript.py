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
This advanced cybersecurity toolkit integrates a wide array of tools with cutting-edge features:
system monitoring, network scanning, remote recon, simulated attacks, log analysis, DNS enumeration,
firewall auditing, Wi-Fi scanning, IDS, DDoS simulation, and more. Designed for educational use with
a stunning terminal UI to rival GUI-based projects.
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
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.tree import Tree
from rich.syntax import Syntax
from rich.markdown import Markdown
import paramiko
import socket
import statistics
from cryptography.fernet import Fernet
import json
import requests
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, send, sniff, DNS, DNSRR, Raw
import matplotlib.pyplot as plt
import dns.resolver
import schedule
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import netifaces
import psutil
import shodan
import nmap
from selenium import webdriver
from bs4 import BeautifulSoup
import asyncio
import aiohttp
import pyshark
import yara
from prettytable import PrettyTable
import hashlib
import magic
import pefile
import volatility3
import r2pipe

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

# Function to display the toolkit banner with ASCII art
def display_banner():
    console.clear()
    banner = """
    [green]   ____      _            _      _   _      _   _ 
    / ___|    (_) __ _  ___| | __ (_) | |    (_) | |
    | |   _   | |/ _` |/ __| |/ / | | | |    | | | |
    | |_| |  | | (_| | (__|   <  | | | |___ | | | |
     ____|  |_|__, |___|_|_|_|_____|_|___||_|_|_|[/green]
    [cyan]CyberSec Toolkit 2025 - Enhanced Edition[/cyan]
    """
    console.print(Panel(banner, title="ThinkCyber 2025", border_style="green"))
    console.print(f"[yellow]Author: ELVIN HUMURA | Date: March 21, 2025[/yellow]")
    console.print("[yellow]Advanced cybersecurity testing for authorized use only.[/yellow]")
    console.print()

# Function to check and install dependencies
def check_dependencies():
    dependencies = ["nmap", "masscan", "hydra", "hping3", "whois", "scapy", "tcpdump", "aircrack-ng"]
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
    python_deps = ["rich", "paramiko", "cryptography", "matplotlib", "requests", "dnspython", "schedule", "reportlab"]
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
        if len(history) < 10:
            return False
        mean = statistics.mean(history)
        std = statistics.stdev(history)
        return abs(current_value - mean) > anomaly_threshold * std

    def monitor_thread():
        while not stop_event.is_set():
            console.clear()
            console.print(Panel("[cyan]=== SYSTEM METRICS MONITOR ===[/cyan]", border_style="blue"))
            console.print(f"[yellow]Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")

            private_ip = socket.gethostbyname(socket.gethostname())
            public_ip = subprocess.check_output(["curl", "-s", "ifconfig.me"]).decode().strip()
            gateway = subprocess.check_output(["ip", "route", "show", "default"]).decode().split()[2]
            console.print(f"[blue]Private IP:[/blue] {private_ip}")
            console.print(f"[blue]Public IP:[/blue] {public_ip}")
            console.print(f"[blue]Gateway:[/blue] {gateway}")

            cpu_usage = float(subprocess.check_output(["top", "-bn1"]).decode().splitlines()[2].split()[1])
            cpu_history.append(cpu_usage)
            if len(cpu_history) > 100:
                cpu_history.pop(0)
            console.print(f"[blue]CPU Usage:[/blue] {cpu_usage}%")
            if detect_anomaly(cpu_usage, cpu_history):
                console.print(Panel(f"[red]ALERT: CPU anomaly detected! Usage: {cpu_usage}%[/red]", border_style="red"))
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

    console.print("[yellow]Scanning network...[/yellow]")
    result = subprocess.check_output(["nmap", "-sn", subnet]).decode()
    ips = re.findall(r"Nmap scan report for ([\d.]+)", result)
    if not ips:
        console.print("[red]No IPs found.[/red]")
        return

    table = Table(title="Available IPs")
    table.add_column("Index", style="green")
    table.add_column("IP", style="yellow")
    for i, ip in enumerate(ips):
        table.add_row(str(i), ip)
    console.print(table)

    choice = Prompt.ask("Select IP index or 'r' for random", default="r")
    target_ip = ips[int(choice)] if choice.isdigit() and int(choice) < len(ips) else ips[0]

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

    creds = {"username": username, "password": password}
    encrypted_creds = cipher.encrypt(json.dumps(creds).encode())
    with open(CRED_FILE, "wb") as f:
        f.write(encrypted_creds)
    logger.info(f"Credentials encrypted and stored in {CRED_FILE}")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(server_ip, username=username, password=password)
        console.print("[green]Connected to remote server.[/green]")

        _, stdout, _ = ssh.exec_command(f"whois {target}")
        whois_output = stdout.read().decode()
        whois_file = os.path.join(OUTPUT_DIR, f"whois_{target}.txt")
        with open(whois_file, "w") as f:
            f.write(whois_output)
        logger.info(f"Whois completed for {target}. Saved to {whois_file}")

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

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task("[yellow]Discovering hosts...", total=None)
        masscan_file = os.path.join(OUTPUT_DIR, "masscan_results.gnmap")
        subprocess.run(["masscan", target_range, "-p", "1-1000", "--rate=1000", "-oG", masscan_file])
        with open(masscan_file) as f:
            hosts = sorted(set(line.split()[1] for line in f if "Host:" in line))
        logger.info(f"Discovered {len(hosts)} hosts in {target_range}")

    console.print("[yellow]Scanning ports and services...[/yellow]")
    nmap_file = os.path.join(OUTPUT_DIR, "nmap_scan.xml")
    subprocess.run(["nmap", "-sS", "-sV", "-A", "-T4", "-oX", nmap_file] + hosts)

    vuln_scores = {}
    with open(nmap_file) as f:
        nmap_data = f.read()
        for host in hosts:
            open_ports = len(re.findall(rf"{host}.*?portid=\"(\d+)\"", nmap_data))
            services = re.findall(rf"{host}.*?service name=\"(.*?)\"", nmap_data)
            score = min(10, open_ports * 0.5 + (3 if "http" in services else 0))
            vuln_scores[host] = score

    table = Table(title="Vulnerability Scores")
    table.add_column("Host", style="green")
    table.add_column("Score (0-10)", style="yellow")
    for host, score in vuln_scores.items():
        table.add_row(host, f"{score:.1f}")
    console.print(table)

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

# NEW Task 6: DNS Enumeration & Spoofing Detection
def dns_enumeration():
    logger.info("Starting DNS Enumeration & Spoofing Detection")
    console.print("[cyan]Enter domain to enumerate (e.g., example.com):[/cyan]")
    domain = Prompt.ask("Domain")
    dns_records = {"A": [], "MX": [], "NS": []}
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task("[yellow]Enumerating DNS records...", total=None)
        for record_type in dns_records.keys():
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    dns_records[record_type].append(str(rdata))
            except Exception as e:
                logger.error(f"DNS {record_type} lookup failed: {e}")

    # Spoofing detection (basic TTL check)
    console.print("[yellow]Checking for potential DNS spoofing...[/yellow]")
    ttl_values = []
    for record in dns_records["A"]:
        pkt = IP(dst="8.8.8.8") / DNS(rd=1, qd=DNSRR(rname=domain, rtype="A"))
        response = send(pkt, verbose=False)
        if response and response.haslayer(DNS):
            ttl_values.append(response[DNS].ttl)
    spoofing_risk = len(set(ttl_values)) > 1  # Inconsistent TTLs may indicate spoofing

    table = Table(title=f"DNS Records for {domain}")
    table.add_column("Type", style="green")
    table.add_column("Record", style="yellow")
    for rtype, records in dns_records.items():
        for rec in records:
            table.add_row(rtype, rec)
    console.print(table)
    console.print(f"[{'red' if spoofing_risk else 'green'}]Spoofing Risk: {'Possible' if spoofing_risk else 'Unlikely'}[/]")

    dns_file = os.path.join(OUTPUT_DIR, f"dns_{domain}.txt")
    with open(dns_file, "w") as f:
        f.write(f"DNS Records for {domain}:\n")
        for rtype, records in dns_records.items():
            f.write(f"{rtype}: {', '.join(records)}\n")
        f.write(f"Spoofing Risk: {'Possible' if spoofing_risk else 'Unlikely'}\n")
    logger.info(f"DNS enumeration completed. Results in {dns_file}")

# NEW Task 7: Firewall Rule Auditor
def firewall_auditor():
    logger.info("Starting Firewall Rule Auditor")
    console.print("[yellow]Analyzing iptables rules...[/yellow]")
    rules = subprocess.check_output(["sudo", "iptables", "-L", "-v", "-n", "--line-numbers"]).decode()
    
    # Basic analysis
    open_ports = re.findall(r"dpt:(\d+)", rules)
    recommendations = []
    if "22" in open_ports:
        recommendations.append("Consider restricting SSH (port 22) to specific IPs.")
    if "80" in open_ports or "443" in open_ports:
        recommendations.append("Ensure HTTP/HTTPS ports are rate-limited against DDoS.")

    console.print(Panel(rules, title="Current iptables Rules", border_style="blue"))
    if recommendations:
        console.print(Panel("\n".join(recommendations), title="Recommendations", border_style="yellow"))

    rules_file = os.path.join(OUTPUT_DIR, "firewall_rules.txt")
    with open(rules_file, "w") as f:
        f.write(rules)
        f.write("\nRecommendations:\n")
        f.write("\n".join(recommendations) if recommendations else "No immediate concerns.")
    logger.info(f"Firewall audit completed. Results in {rules_file}")

# NEW Task 8: Wi-Fi Security Scanner
def wifi_scanner():
    logger.info("Starting Wi-Fi Security Scanner")
    console.print("[yellow]Ensure aircrack-ng is installed and run as root.[/yellow]")
    interface = Prompt.ask("Enter wireless interface (e.g., wlan0)")
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task("[yellow]Scanning Wi-Fi networks...", total=None)
        subprocess.run(["sudo", "airmon-ng", "start", interface])
        scan_output = subprocess.check_output(["sudo", "airodump-ng", interface, "-w", os.path.join(OUTPUT_DIR, "wifi_scan"), "--output-format", "csv", "-t", "10"]).decode()

    wifi_file = os.path.join(OUTPUT_DIR, "wifi_scan-01.csv")
    networks = []
    if os.path.exists(wifi_file):
        with open(wifi_file) as f:
            for line in f:
                if "WPA" in line or "WEP" in line:
                    fields = line.split(",")
                    networks.append({"BSSID": fields[0], "ESSID": fields[13].strip(), "Encryption": fields[5]})

    table = Table(title="Wi-Fi Networks")
    table.add_column("BSSID", style="green")
    table.add_column("ESSID", style="yellow")
    table.add_column("Encryption", style="blue")
    for net in networks:
        table.add_row(net["BSSID"], net["ESSID"], net["Encryption"])
    console.print(table)
    logger.info(f"Wi-Fi scan completed. Results in {wifi_file}")

# NEW Task 9: Intrusion Detection System (IDS)
def intrusion_detection():
    logger.info("Starting Intrusion Detection System")
    console.print("[cyan]Enter interface to monitor (e.g., eth0):[/cyan]")
    interface = Prompt.ask("Interface")
    console.print("[yellow]Monitoring for suspicious packets (Ctrl+C to stop)...[/yellow]")

    def packet_callback(packet):
        if packet.haslayer(TCP) and packet[TCP].flags == "S":  # SYN flood detection
            src_ip = packet[IP].src
            console.print(Panel(f"[red]Potential SYN flood from {src_ip}[/red]", border_style="red"))
            logger.warning(f"SYN flood detected from {src_ip}")

    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except PermissionError:
        console.print("[red]Error: Run as root for packet sniffing.[/red]")
    except KeyboardInterrupt:
        console.print("[green]IDS stopped.[/green]")

# NEW Task 10: DDoS Mitigation Simulator
def ddos_mitigation():
    logger.info("Starting DDoS Mitigation Simulator")
    console.print("[cyan]Enter target IP to simulate DDoS against:[/cyan]")
    target_ip = Prompt.ask("Target IP")
    
    console.print("[yellow]Simulating DDoS (SYN flood)...[/yellow]")
    packet = IP(dst=target_ip) / TCP(dport=80, flags="S")
    send(packet, count=200, verbose=False)
    
    mitigation = [
        "iptables -A INPUT -p tcp --syn -m limit --limit 25/second --limit-burst 100 -j ACCEPT",
        "iptables -A INPUT -p tcp --syn -j DROP"
    ]
    console.print(Panel("\n".join(mitigation), title="Suggested Mitigation Rules", border_style="green"))
    logger.info(f"DDoS simulation completed on {target_ip}")

# NEW Task 11: Advanced Network Protocol Analyzer
def protocol_analyzer():
    logger.info("Starting Advanced Network Protocol Analyzer")
    console.print("[cyan]Enter interface to analyze (e.g., eth0):[/cyan]")
    interface = Prompt.ask("Interface")
    
    protocols = defaultdict(int)
    suspicious_packets = []
    
    def packet_callback(packet):
        if IP in packet:
            protocols[packet[IP].proto] += 1
            
            # Deep packet inspection
            if TCP in packet and packet[TCP].flags == "S":
                suspicious_packets.append(("SYN Flood", packet[IP].src))
            elif ICMP in packet and packet[ICMP].type == 8:
                suspicious_packets.append(("ICMP Ping", packet[IP].src))
            elif UDP in packet and packet[UDP].dport == 53:
                suspicious_packets.append(("DNS Query", packet[IP].src))
                
    with Progress() as progress:
        task = progress.add_task("[cyan]Analyzing network traffic...", total=None)
        try:
            sniff(iface=interface, prn=packet_callback, timeout=30)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return

    # Create protocol distribution visualization
    plt.figure(figsize=(10, 6))
    plt.bar(protocols.keys(), protocols.values())
    plt.title("Protocol Distribution")
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")
    plt.savefig(os.path.join(OUTPUT_DIR, "protocol_dist.png"))
    
    # Display results in a beautiful table
    table = Table(title="Network Protocol Analysis")
    table.add_column("Protocol", style="cyan")
    table.add_column("Count", style="green")
    table.add_column("Percentage", style="yellow")
    
    total_packets = sum(protocols.values())
    for proto, count in protocols.items():
        percentage = (count / total_packets) * 100
        table.add_row(str(proto), str(count), f"{percentage:.2f}%")
    
    console.print(table)
    
    # Display suspicious activities
    if suspicious_packets:
        sus_table = Table(title="Suspicious Activities")
        sus_table.add_column("Type", style="red")
        sus_table.add_column("Source IP", style="yellow")
        sus_table.add_column("Count", style="green")
        
        activity_count = Counter(suspicious_packets)
        for (activity, ip), count in activity_count.items():
            sus_table.add_row(activity, ip, str(count))
        
        console.print(sus_table)

# NEW Task 12: Malware Analysis Lab
def malware_analysis():
    logger.info("Starting Malware Analysis Lab")
    console.print("[cyan]Enter path to suspicious file:[/cyan]")
    file_path = Prompt.ask("File Path")
    
    if not os.path.exists(file_path):
        console.print("[red]File not found.[/red]")
        return
        
    # Create analysis directory
    analysis_dir = os.path.join(OUTPUT_DIR, "malware_analysis")
    os.makedirs(analysis_dir, exist_ok=True)
    
    # Basic file analysis
    file_info = {}
    file_info["size"] = os.path.getsize(file_path)
    file_info["type"] = magic.from_file(file_path)
    file_info["mime"] = magic.from_file(file_path, mime=True)
    
    # Calculate hashes
    with open(file_path, "rb") as f:
        data = f.read()
        file_info["md5"] = hashlib.md5(data).hexdigest()
        file_info["sha1"] = hashlib.sha1(data).hexdigest()
        file_info["sha256"] = hashlib.sha256(data).hexdigest()
    
    # PE file analysis if applicable
    if file_info["mime"] == "application/x-dosexec":
        try:
            pe = pefile.PE(file_path)
            file_info["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            file_info["sections"] = [section.Name.decode().rstrip('\x00') for section in pe.sections]
            file_info["imports"] = list(pe.DIRECTORY_ENTRY_IMPORT[0].dll.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT)
        except Exception as e:
            file_info["pe_error"] = str(e)
    
    # YARA rules matching
    rules = yara.compile(source='rule suspicious { strings: $a = "malware" condition: $a }')
    matches = rules.match(file_path)
    file_info["yara_matches"] = [str(match) for match in matches]
    
    # Display results
    console.print(Panel("[cyan]Malware Analysis Results[/cyan]", border_style="blue"))
    
    table = Table(title="File Information")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="yellow")
    
    for key, value in file_info.items():
        if isinstance(value, list):
            table.add_row(key, "\n".join(value))
        else:
            table.add_row(key, str(value))
    
    console.print(table)
    
    # Save detailed report
    report_path = os.path.join(analysis_dir, "analysis_report.txt")
    with open(report_path, "w") as f:
        json.dump(file_info, f, indent=4)
    
    console.print(f"[green]Detailed analysis report saved to: {report_path}[/green]")

# NEW Task 13: Web Application Security Scanner
def web_security_scanner():
    logger.info("Starting Web Application Security Scanner")
    console.print("[cyan]Enter target URL:[/cyan]")
    target_url = Prompt.ask("URL")
    
    vulnerabilities = []
    
    # Initialize headless browser
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    
    try:
        driver = webdriver.Chrome(options=options)
        
        # Test for XSS vulnerabilities
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ]
        
        for payload in xss_payloads:
            test_url = f"{target_url}?q={payload}"
            driver.get(test_url)
            if "alert" in driver.page_source:
                vulnerabilities.append(("XSS", test_url))
        
        # Test for SQL injection
        sql_payloads = ["' OR '1'='1", "1' OR '1'='1"]
        for payload in sql_payloads:
            test_url = f"{target_url}?id={payload}"
            driver.get(test_url)
            if "error in your SQL syntax" in driver.page_source:
                vulnerabilities.append(("SQL Injection", test_url))
        
        # Directory traversal test
        traversal_paths = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"]
        for path in traversal_paths:
            test_url = f"{target_url}/{path}"
            response = requests.get(test_url)
            if "root:" in response.text or "[extensions]" in response.text:
                vulnerabilities.append(("Directory Traversal", test_url))
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
    finally:
        driver.quit()
    
    # Display results
    table = Table(title="Web Security Scan Results")
    table.add_column("Vulnerability", style="red")
    table.add_column("URL", style="yellow")
    
    for vuln_type, url in vulnerabilities:
        table.add_row(vuln_type, url)
    
    console.print(table)
    
    # Save report
    report_path = os.path.join(OUTPUT_DIR, "web_security_report.txt")
    with open(report_path, "w") as f:
        for vuln_type, url in vulnerabilities:
            f.write(f"{vuln_type}: {url}\n")
    
    console.print(f"[green]Web security report saved to: {report_path}[/green]")

# NEW Task 14: Memory Forensics Analyzer
def memory_forensics():
    logger.info("Starting Memory Forensics Analyzer")
    console.print("[cyan]Enter path to memory dump file:[/cyan]")
    dump_path = Prompt.ask("Memory Dump Path")
    
    if not os.path.exists(dump_path):
        console.print("[red]Memory dump file not found.[/red]")
        return
    
    # Initialize Volatility3
    console.print("[yellow]Analyzing memory dump...[/yellow]")
    
    # Create analysis directory
    analysis_dir = os.path.join(OUTPUT_DIR, "memory_forensics")
    os.makedirs(analysis_dir, exist_ok=True)
    
    try:
        # Process list analysis
        processes = volatility3.framework.automagic.run(
            "windows.pslist.PsList",
            dump_path
        )
        
        # Network connections
        connections = volatility3.framework.automagic.run(
            "windows.netscan.NetScan",
            dump_path
        )
        
        # Loaded DLLs
        dlls = volatility3.framework.automagic.run(
            "windows.dlllist.DllList",
            dump_path
        )
        
        # Display results
        console.print(Panel("[cyan]Memory Forensics Results[/cyan]", border_style="blue"))
        
        # Process table
        proc_table = Table(title="Running Processes")
        proc_table.add_column("PID", style="cyan")
        proc_table.add_column("Name", style="yellow")
        proc_table.add_column("Start Time", style="green")
        
        for proc in processes:
            proc_table.add_row(str(proc.pid), proc.name, str(proc.create_time))
        
        console.print(proc_table)
        
        # Network connections table
        net_table = Table(title="Network Connections")
        net_table.add_column("Local Address", style="cyan")
        net_table.add_column("Remote Address", style="yellow")
        net_table.add_column("State", style="green")
        
        for conn in connections:
            net_table.add_row(
                f"{conn.local_addr}:{conn.local_port}",
                f"{conn.remote_addr}:{conn.remote_port}",
                conn.state
            )
        
        console.print(net_table)
        
        # Save detailed report
        report_path = os.path.join(analysis_dir, "memory_analysis.txt")
        with open(report_path, "w") as f:
            f.write("=== Memory Forensics Report ===\n\n")
            f.write("Processes:\n")
            for proc in processes:
                f.write(f"PID: {proc.pid}, Name: {proc.name}, Start: {proc.create_time}\n")
            
            f.write("\nNetwork Connections:\n")
            for conn in connections:
                f.write(f"{conn.local_addr}:{conn.local_port} -> {conn.remote_addr}:{conn.remote_port} ({conn.state})\n")
            
            f.write("\nLoaded DLLs:\n")
            for dll in dlls:
                f.write(f"{dll.path}\n")
        
        console.print(f"[green]Memory analysis report saved to: {report_path}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error during memory analysis: {e}[/red]")

# NEW Task 15: Binary Analysis Tool
def binary_analysis():
    logger.info("Starting Binary Analysis Tool")
    console.print("[cyan]Enter path to binary file:[/cyan]")
    binary_path = Prompt.ask("Binary Path")
    
    if not os.path.exists(binary_path):
        console.print("[red]Binary file not found.[/red]")
        return
    
    # Initialize radare2
    r2 = r2pipe.open(binary_path)
    
    try:
        # Analyze all
        r2.cmd("aaa")
        
        # Get basic information
        info = json.loads(r2.cmd("ij"))
        
        # Get functions
        functions = json.loads(r2.cmd("aflj"))
        
        # Get strings
        strings = json.loads(r2.cmd("izj"))
        
        # Get imports
        imports = json.loads(r2.cmd("iij"))
        
        # Display results
        console.print(Panel("[cyan]Binary Analysis Results[/cyan]", border_style="blue"))
        
        # Basic info table
        info_table = Table(title="Binary Information")
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="yellow")
        
        info_table.add_row("File Type", info["core"]["type"])
        info_table.add_row("Architecture", info["bin"]["arch"])
        info_table.add_row("OS", info["bin"]["os"])
        info_table.add_row("Entry Point", hex(info["bin"]["entry"]))
        
        console.print(info_table)
        
        # Functions table
        func_table = Table(title="Interesting Functions")
        func_table.add_column("Name", style="cyan")
        func_table.add_column("Address", style="yellow")
        func_table.add_column("Size", style="green")
        
        for func in functions[:10]:  # Show top 10 functions
            func_table.add_row(
                func["name"],
                hex(func["offset"]),
                str(func["size"])
            )
        
        console.print(func_table)
        
        # Strings table
        strings_table = Table(title="Interesting Strings")
        strings_table.add_column("String", style="cyan")
        strings_table.add_column("Type", style="yellow")
        
        for string in strings[:10]:  # Show top 10 strings
            strings_table.add_row(string["string"], string["type"])
        
        console.print(strings_table)
        
        # Save detailed report
        report_path = os.path.join(OUTPUT_DIR, "binary_analysis.txt")
        with open(report_path, "w") as f:
            f.write("=== Binary Analysis Report ===\n\n")
            f.write(json.dumps(info, indent=4))
            f.write("\n\nFunctions:\n")
            f.write(json.dumps(functions, indent=4))
            f.write("\n\nStrings:\n")
            f.write(json.dumps(strings, indent=4))
            f.write("\n\nImports:\n")
            f.write(json.dumps(imports, indent=4))
        
        console.print(f"[green]Binary analysis report saved to: {report_path}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error during binary analysis: {e}[/red]")
    finally:
        r2.quit()

# NEW Feature: Automated Report Generation
def generate_pdf_report():
    report_file = os.path.join(OUTPUT_DIR, "cybersec_report.pdf")
    doc = SimpleDocTemplate(report_file, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [Paragraph("CyberSec Toolkit 2025 Report", styles["Title"])]
    
    for filename in os.listdir(OUTPUT_DIR):
        if filename.endswith(".txt"):
            with open(os.path.join(OUTPUT_DIR, filename)) as f:
                story.append(Paragraph(f"Results from {filename}", styles["Heading2"]))
                story.append(Paragraph(f.read(), styles["BodyText"]))
                story.append(Spacer(1, 12))
    
    doc.build(story)
    console.print(f"[green]PDF report generated: {report_file}[/green]")
    logger.info(f"PDF report generated: {report_file}")

# Function to display the main menu with dashboard
def display_menu():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="menu", ratio=1),
        Layout(name="footer", size=3)
    )
    layout["header"].update(Panel("[cyan]CyberSec Toolkit 2025 Dashboard[/cyan]", border_style="green"))
    menu_table = Table(title="Select a Task", show_header=False, expand=True)
    menu_table.add_row("[green][1][/green] System Metrics Monitoring - Real-time with anomaly detection")
    menu_table.add_row("[green][2][/green] Security Testing - Simulated attacks with packet crafting")
    menu_table.add_row("[green][3][/green] Remote Reconnaissance - SSH-based with encrypted creds")
    menu_table.add_row("[green][4][/green] Network Scanning - Vulnerability scoring and visualization")
    menu_table.add_row("[green][5][/green] Auth Log Analyzer - With threat intelligence lookup")
    menu_table.add_row("[green][6][/green] DNS Enumeration - With spoofing detection")
    menu_table.add_row("[green][7][/green] Firewall Rule Auditor - Analyze and suggest rules")
    menu_table.add_row("[green][8][/green] Wi-Fi Security Scanner - Assess wireless networks")
    menu_table.add_row("[green][9][/green] Intrusion Detection - Real-time packet monitoring")
    menu_table.add_row("[green][10][/green] DDoS Mitigation - Simulate and mitigate")
    menu_table.add_row("[green][11][/green] Advanced Network Protocol Analyzer")
    menu_table.add_row("[green][12][/green] Malware Analysis Lab")
    menu_table.add_row("[green][13][/green] Web Application Security Scanner")
    menu_table.add_row("[green][14][/green] Memory Forensics Analyzer")
    menu_table.add_row("[green][15][/green] Binary Analysis Tool")
    menu_table.add_row("[green][0][/green] Exit - Quit the toolkit")
    layout["menu"].update(menu_table)
    layout["footer"].update(Panel(f"[yellow]Output Directory: {OUTPUT_DIR}[/yellow]", border_style="blue"))
    
    console.print(layout)
    return Prompt.ask("Enter your choice (0-15)", choices=[str(i) for i in range(16)])

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
            elif choice == "6":
                dns_enumeration()
            elif choice == "7":
                firewall_auditor()
            elif choice == "8":
                wifi_scanner()
            elif choice == "9":
                intrusion_detection()
            elif choice == "10":
                ddos_mitigation()
            elif choice == "11":
                protocol_analyzer()
            elif choice == "12":
                malware_analysis()
            elif choice == "13":
                web_security_scanner()
            elif choice == "14":
                memory_forensics()
            elif choice == "15":
                binary_analysis()
            elif choice == "0":
                console.print("[green]Thank you for using CyberSec Toolkit 2025![/green]")
                console.print(f"[yellow]Logs and results saved to: {OUTPUT_DIR}[/yellow]")
                if Confirm.ask("Generate PDF report?", default=True):
                    generate_pdf_report()
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