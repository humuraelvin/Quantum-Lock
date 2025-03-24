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
from rich.spinner import Spinner
from rich.box import DOUBLE
from rich.status import Status
from rich.columns import Columns
from rich.align import Align
import paramiko
import socket
import statistics
from cryptography.fernet import Fernet
import json
import requests
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, send, sniff, DNS, DNSRR, Raw, sr1, srp
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
import whois
import ssl
import OpenSSL
import pytesseract
from PIL import Image
import cv2
import numpy as np
from faker import Faker
import virustotal_python
import sqlite3
from threading import Lock
import dns.reversename
import dns.query
import dns.zone
import dns.tsigkeyring
from dns.update import Update
import pygeoip
import maxminddb
from rich.progress import TaskID
import base64
import shutil
import aiofiles
import concurrent.futures
from datetime import datetime, timedelta

# Initialize Faker for synthetic data generation
fake = Faker()

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

# Database setup for persistent storage
DB_FILE = os.path.join(OUTPUT_DIR, "cybersec_db.sqlite")
db_lock = Lock()

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            task TEXT,
            target TEXT,
            result TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            type TEXT,
            details TEXT
        )''')
        conn.commit()
    logger.info("Database initialized.")

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

# Task 16: Automated OSINT Collection
async def osint_collection():
    logger.info("Starting Automated OSINT Collection")
    console.print("[cyan]Enter target (domain, IP, or username):[/cyan]")
    target = Prompt.ask("Target")
    
    async def fetch_web_content():
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"http://{target}") as resp:
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    return {"title": soup.title.string if soup.title else "N/A", "links": [a["href"] for a in soup.find_all("a", href=True)]}
            except Exception as e:
                return {"error": str(e)}

    async def fetch_whois():
        try:
            w = whois.whois(target)
            return {"registrar": w.registrar, "creation_date": str(w.creation_date)}
        except Exception as e:
            return {"error": str(e)}

    async def fetch_shodan(api_key):
        api = shodan.Shodan(api_key)
        try:
            result = api.host(target)
            return {"os": result.get("os", "N/A"), "ports": result.get("ports", [])}
        except Exception as e:
            return {"error": str(e)}

    with Progress(SpinnerColumn(), TextColumn("[yellow]Collecting OSINT...[/yellow]"), transient=True) as progress:
        task = progress.add_task("OSINT", total=None)
        shodan_key = Prompt.ask("Shodan API Key (optional, press Enter to skip)", default="")
        results = await asyncio.gather(
            fetch_web_content(),
            fetch_whois(),
            fetch_shodan(shodan_key) if shodan_key else asyncio.sleep(0, result={"skipped": True})
        )

    osint_data = {"web": results[0], "whois": results[1], "shodan": results[2]}
    table = Table(title=f"OSINT Results for {target}", box=DOUBLE)
    table.add_column("Source", style="cyan")
    table.add_column("Details", style="yellow")
    for source, data in osint_data.items():
        table.add_row(source, "\n".join(f"{k}: {v}" for k, v in data.items()))
    console.print(table)

    osint_file = os.path.join(OUTPUT_DIR, f"osint_{target}.json")
    with open(osint_file, "w") as f:
        json.dump(osint_data, f, indent=4)
    logger.info(f"OSINT collection completed. Results in {osint_file}")

# Task 17: SSL/TLS Security Auditor
def ssl_auditor():
    logger.info("Starting SSL/TLS Security Auditor")
    console.print("[cyan]Enter domain to audit (e.g., example.com):[/cyan]")
    domain = Prompt.ask("Domain")
    
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        issuer = x509.get_issuer().CN
        expiry = datetime.strptime(x509.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        cipher_suite = ssl.create_connection((domain, 443)).get_ciphers()

        issues = []
        if expiry < datetime.now():
            issues.append("Certificate expired!")
        if "RC4" in str(cipher_suite):
            issues.append("Weak RC4 cipher detected!")
        if "TLSv1.0" in str(cipher_suite):
            issues.append("Outdated TLSv1.0 detected!")

        panel = Panel(
            f"[green]Issuer:[/green] {issuer}\n"
            f"[green]Expiry:[/green] {expiry}\n"
            f"[green]Ciphers:[/green] {len(cipher_suite)} detected\n"
            f"[{'red' if issues else 'green'}]Issues:[/] {', '.join(issues) if issues else 'None'}",
            title=f"SSL/TLS Audit for {domain}",
            border_style="blue", box=DOUBLE
        )
        console.print(panel)

        ssl_file = os.path.join(OUTPUT_DIR, f"ssl_audit_{domain}.txt")
        with open(ssl_file, "w") as f:
            f.write(f"Issuer: {issuer}\nExpiry: {expiry}\nCiphers: {cipher_suite}\nIssues: {issues}")
        logger.info(f"SSL audit completed. Results in {ssl_file}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

# Task 18: Automated Phishing Detection
def phishing_detection():
    logger.info("Starting Automated Phishing Detection")
    console.print("[cyan]Enter email file path or URL to analyze:[/cyan]")
    target = Prompt.ask("Target")
    
    if os.path.isfile(target):
        with open(target, "r") as f:
            content = f.read()
    else:
        content = requests.get(target).text

    suspicious_indicators = {
        "spoofed_domain": re.search(r"(login|account|verify).*(google|paypal|bank)", content, re.IGNORECASE),
        "urgency": re.search(r"(urgent|immediate|now)", content, re.IGNORECASE),
        "malicious_link": re.search(r"https?://[^\s]+", content)
    }
    
    table = Table(title="Phishing Indicators", box=DOUBLE)
    table.add_column("Indicator", style="cyan")
    table.add_column("Detected", style="yellow")
    for indicator, match in suspicious_indicators.items():
        table.add_row(indicator, "[red]Yes[/red]" if match else "[green]No[/green]")
    console.print(table)

    risk_score = sum(1 for v in suspicious_indicators.values() if v) * 25
    console.print(Panel(f"[yellow]Phishing Risk Score: {risk_score}/100[/yellow]", border_style="red" if risk_score > 50 else "green"))

    phishing_file = os.path.join(OUTPUT_DIR, "phishing_report.txt")
    with open(phishing_file, "w") as f:
        f.write(f"Target: {target}\nRisk Score: {risk_score}\nIndicators: {suspicious_indicators}")
    logger.info(f"Phishing detection completed. Report in {phishing_file}")

# Task 19: Dark Web Scanner
async def dark_web_scanner():
    logger.info("Starting Dark Web Scanner")
    console.print("[cyan]Enter keyword to search (e.g., company name):[/cyan]")
    keyword = Prompt.ask("Keyword")
    
    # Simulated dark web search (replace with real Tor integration if desired)
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://api.onionsearch.com/search?q={keyword}") as resp:
            data = await resp.json()
    
    findings = data.get("results", [])
    table = Table(title=f"Dark Web Findings for '{keyword}'", box=DOUBLE)
    table.add_column("Title", style="cyan")
    table.add_column("URL", style="yellow")
    for finding in findings[:5]:  # Top 5 results
        table.add_row(finding.get("title", "N/A"), finding.get("url", "N/A"))
    console.print(table)

    dark_file = os.path.join(OUTPUT_DIR, f"darkweb_{keyword}.json")
    with open(dark_file, "w") as f:
        json.dump(findings, f, indent=4)
    logger.info(f"Dark web scan completed. Results in {dark_file}")

# Task 20: Automated Exploit Framework
def exploit_framework():
    logger.info("Starting Automated Exploit Framework")
    console.print("[cyan]Enter target IP:[/cyan]")
    target_ip = Prompt.ask("Target IP")
    
    nm = nmap.PortScanner()
    nm.scan(target_ip, "22-443")
    exploits = []
    
    for port in nm[target_ip]["tcp"]:
        if port == 22 and nm[target_ip]["tcp"][port]["state"] == "open":
            exploits.append("SSH Brute Force (Hydra simulation)")
        elif port == 80 and "http" in nm[target_ip]["tcp"][port]["name"]:
            exploits.append("HTTP Exploit (e.g., CVE-2021-3129 simulation)")

    with Progress(SpinnerColumn(), TextColumn("[yellow]Simulating exploits...[/yellow]")) as progress:
        task = progress.add_task("Exploits", total=len(exploits))
        for exploit in exploits:
            time.sleep(2)  # Simulate exploit execution
            progress.update(task, advance=1)

    table = Table(title=f"Exploit Results for {target_ip}", box=DOUBLE)
    table.add_column("Exploit", style="cyan")
    table.add_column("Status", style="yellow")
    for exploit in exploits:
        table.add_row(exploit, "[green]Simulated[/green]")
    console.print(table)

    exploit_file = os.path.join(OUTPUT_DIR, f"exploit_{target_ip}.txt")
    with open(exploit_file, "w") as f:
        f.write(f"Target: {target_ip}\nExploits: {exploits}")
    logger.info(f"Exploit simulation completed. Results in {exploit_file}")

# Task 21: Synthetic Attack Generator
def synthetic_attack_generator():
    logger.info("Starting Synthetic Attack Generator")
    console.print("[cyan]Enter target IP:[/cyan]")
    target_ip = Prompt.ask("Target IP")
    
    attack_types = [
        ("SYN Flood", IP(dst=target_ip) / TCP(dport=80, flags="S")),
        ("ICMP Ping Flood", IP(dst=target_ip) / ICMP()),
        ("UDP Flood", IP(dst=target_ip) / UDP(dport=53))
    ]
    
    with Live(Panel("[yellow]Generating synthetic attacks...[/yellow]", box=DOUBLE), refresh_per_second=4) as live:
        for attack_name, packet in attack_types:
            live.update(Panel(f"[cyan]Running: {attack_name}[/cyan]", box=DOUBLE))
            send(packet, count=50, verbose=False)
            time.sleep(1)
    
    console.print(f"[green]Synthetic attacks completed on {target_ip}[/green]")
    logger.info(f"Synthetic attacks generated on {target_ip}")

# Task 22: Advanced Packet Forensics
def packet_forensics():
    logger.info("Starting Advanced Packet Forensics")
    console.print("[cyan]Enter PCAP file path:[/cyan]")
    pcap_file = Prompt.ask("PCAP File")
    
    if not os.path.exists(pcap_file):
        console.print("[red]File not found.[/red]")
        return
    
    cap = pyshark.FileCapture(pcap_file)
    packets = list(cap)
    
    proto_count = Counter(pkt.protocol for pkt in packets if hasattr(pkt, "protocol"))
    suspicious = [pkt for pkt in packets if hasattr(pkt, "tcp") and pkt.tcp.flags_syn == "1" and pkt.tcp.flags_ack == "0"]
    
    table = Table(title="Packet Forensics Summary", box=DOUBLE)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="yellow")
    table.add_row("Total Packets", str(len(packets)))
    table.add_row("Protocols", ", ".join(f"{k}: {v}" for k, v in proto_count.items()))
    table.add_row("Suspicious SYN", str(len(suspicious)))
    console.print(table)

    forensics_file = os.path.join(OUTPUT_DIR, "packet_forensics.txt")
    with open(forensics_file, "w") as f:
        f.write(f"Total Packets: {len(packets)}\nProtocols: {dict(proto_count)}\nSuspicious: {len(suspicious)}")
    logger.info(f"Packet forensics completed. Results in {forensics_file}")

# Task 23: GeoIP Threat Mapping
def geoip_threat_mapping():
    logger.info("Starting GeoIP Threat Mapping")
    console.print("[cyan]Enter IP list file or single IP:[/cyan]")
    target = Prompt.ask("Target")
    
    gi = pygeoip.GeoIP("GeoIP.dat")  # Requires GeoIP database
    threats = []
    
    if os.path.isfile(target):
        with open(target) as f:
            ips = f.read().splitlines()
    else:
        ips = [target]
    
    for ip in ips:
        try:
            loc = gi.record_by_addr(ip)
            threats.append({"ip": ip, "country": loc["country_name"], "city": loc.get("city", "N/A")})
        except Exception as e:
            logger.error(f"GeoIP lookup failed for {ip}: {e}")

    table = Table(title="GeoIP Threat Map", box=DOUBLE)
    table.add_column("IP", style="cyan")
    table.add_column("Country", style="yellow")
    table.add_column("City", style="green")
    for threat in threats:
        table.add_row(threat["ip"], threat["country"], threat["city"])
    console.print(table)

    geoip_file = os.path.join(OUTPUT_DIR, "geoip_map.json")
    with open(geoip_file, "w") as f:
        json.dump(threats, f, indent=4)
    logger.info(f"GeoIP mapping completed. Results in {geoip_file}")

# Task 24: SOC Automation Dashboard
def soc_automation():
    logger.info("Starting SOC Automation Dashboard")
    
    def update_dashboard(live):
        while True:
            layout = create_dashboard()
            threats = []
            with sqlite3.connect(DB_FILE) as conn:
                c = conn.cursor()
                c.execute("SELECT ip, type, details FROM threats ORDER BY timestamp DESC LIMIT 5")
                threats = c.fetchall()
            
            threat_table = Table(title="Recent Threats", box=DOUBLE)
            threat_table.add_column("IP", style="cyan")
            threat_table.add_column("Type", style="yellow")
            threat_table.add_column("Details", style="green")
            for ip, ttype, details in threats:
                threat_table.add_row(ip, ttype, details)
            
            layout["actions"].update(threat_table)
            live.update(layout)
            time.sleep(5)
    
    with Live(create_dashboard(), refresh_per_second=4) as live:
        threading.Thread(target=update_dashboard, args=(live,), daemon=True).start()
        try:
            Prompt.ask("[yellow]Press Enter to exit dashboard...[/yellow]")
        except KeyboardInterrupt:
            pass
    console.print("[green]SOC Dashboard stopped.[/green]")

# Task 25: Automated Honeypot Deployer
def honeypot_deployer():
    logger.info("Starting Automated Honeypot Deployer")
    console.print("[cyan]Enter port to deploy honeypot on:[/cyan]")
    port = int(Prompt.ask("Port", default="8080"))
    
    def honeypot_server():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", port))
        server.listen(5)
        console.print(f"[green]Honeypot running on port {port}[/green]")
        
        while True:
            client, addr = server.accept()
            logger.warning(f"Honeypot hit from {addr}")
            with sqlite3.connect(DB_FILE) as conn:
                c = conn.cursor()
                c.execute("INSERT INTO threats (timestamp, ip, type, details) VALUES (?, ?, ?, ?)",
                         (datetime.now().isoformat(), addr[0], "Honeypot", "Connection attempt"))
                conn.commit()
            client.send(b"Welcome to the honeypot!\n")
            client.close()
    
    threading.Thread(target=honeypot_server, daemon=True).start()
    console.print("[yellow]Honeypot deployed. Press Enter to stop...[/yellow]")
    input()
    logger.info("Honeypot stopped.")

# Add this new function after Task 25 (Automated Honeypot Deployer)
def network_devices():
    logger.info("Starting Network Device Scanner")
    console.print("[cyan]Enter network interface (e.g., eth0, wlan0) or press Enter for default:[/cyan]")
    interface = Prompt.ask("Interface", default=netifaces.gateways()['default'][netifaces.AF_INET][1])
    
    # Get local IP and subnet
    try:
        addrs = netifaces.ifaddresses(interface)
        ip_info = addrs[netifaces.AF_INET][0]
        local_ip = ip_info['addr']
        netmask = ip_info['netmask']
        
        # Calculate subnet
        from ipaddress import ip_network
        subnet = str(ip_network(f"{local_ip}/{netmask}", strict=False))
        console.print(f"[yellow]Scanning subnet: {subnet} on interface {interface}...[/yellow]")
    except Exception as e:
        console.print(f"[red]Error getting network info: {e}[/red]")
        return

    devices = {}
    
    def arp_scan():
        # Use ARP to discover devices
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(arp_request, timeout=2, verbose=False, iface=interface)
        
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror):
                hostname = "Unknown"
            devices[ip] = {"mac": mac, "hostname": hostname}
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task("[yellow]Discovering devices...", total=None)
        arp_thread = threading.Thread(target=arp_scan)
        arp_thread.start()
        arp_thread.join()

    if not devices:
        console.print("[red]No devices found on the network.[/red]")
        return

    # Display results in a table
    table = Table(title=f"Devices on {interface} ({subnet})", box=DOUBLE)
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address", style="yellow")
    table.add_column("Hostname", style="green")
    
    for ip, info in sorted(devices.items()):
        table.add_row(ip, info["mac"], info["hostname"])
    
    console.print(table)
    
    # Save results
    devices_file = os.path.join(OUTPUT_DIR, f"network_devices_{interface}.json")
    with open(devices_file, "w") as f:
        json.dump(devices, f, indent=4)
    
    console.print(f"[green]Scan completed. Results saved to: {devices_file}[/green]")
    logger.info(f"Network device scan completed. Found {len(devices)} devices.")

def zero_day_predictor():
    logger.info("Starting Zero-Day Vulnerability Predictor")
    console.print("[cyan]Enter target IP or hostname to analyze:[/cyan]")
    target = Prompt.ask("Target")
    
    # Step 1: Scan target with nmap
    console.print("[yellow]Scanning target for services...[/yellow]")
    nm = nmap.PortScanner()
    try:
        nm.scan(target, "1-65535", arguments="-sV -T4")
    except Exception as e:
        console.print(f"[red]Nmap scan failed: {e}[/red]")
        return
    
    if target not in nm.all_hosts():
        console.print("[red]No response from target.[/red]")
        return
    
    # Step 2: Collect service data
    services = []
    for port in nm[target].all_tcp():
        if nm[target]['tcp'][port]['state'] == 'open':
            service = {
                "port": port,
                "name": nm[target]['tcp'][port].get('name', 'unknown'),
                "version": nm[target]['tcp'][port].get('version', ''),
                "product": nm[target]['tcp'][port].get('product', '')
            }
            services.append(service)
    
    if not services:
        console.print("[red]No open services detected.[/red]")
        return
    
    # Step 3: Query NVD for historical CVEs (simplified)
    console.print("[yellow]Checking historical vulnerabilities...[/yellow]")
    predictions = []
    nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    for service in services:
        product = service['product'] or service['name']
        if not product or product == 'unknown':
            continue
        
        # Heuristic scoring factors
        score = 0
        details = {"service": f"{product} on port {service['port']}"}
        
        # Factor 1: Historical CVE count (simplified lookup)
        try:
            response = requests.get(f"{nvd_base_url}?keywordSearch={product}&resultsPerPage=1")
            if response.status_code == 200:
                data = response.json()
                total_cves = data.get('totalResults', 0)
                score += min(total_cves // 10, 5)  # Cap at 5 points
                details["cve_count"] = total_cves
            else:
                details["cve_count"] = "N/A"
        except Exception as e:
            logger.error(f"NVD lookup failed for {product}: {e}")
            details["cve_count"] = "Error"
        
        # Factor 2: Service age (heuristic based on version or name)
        if service['version']:
            try:
                version_year = int(service['version'].split('.')[0])
                if version_year < (datetime.now().year - 5):
                    score += 3
                    details["age_risk"] = "Old version detected"
            except ValueError:
                details["age_risk"] = "Unknown"
        else:
            score += 2  # No version info might indicate obscurity
            details["age_risk"] = "Version not specified"
        
        # Factor 3: Complexity (simplified)
        complex_services = ['http', 'apache', 'nginx', 'mysql', 'ssh']
        if service['name'].lower() in complex_services:
            score += 2
            details["complexity"] = "High"
        else:
            details["complexity"] = "Low"
        
        # Factor 4: Unusual port usage
        common_ports = {22: 'ssh', 80: 'http', 443: 'https', 3306: 'mysql'}
        if service['port'] not in common_ports or common_ports.get(service['port']) != service['name']:
            score += 2
            details["port_usage"] = "Unusual"
        else:
            details["port_usage"] = "Typical"
        
        # Cap score at 10
        score = min(score, 10)
        details["zero_day_score"] = score
        predictions.append(details)
    
    # Step 4: Display results
    table = Table(title=f"Zero-Day Vulnerability Predictions for {target}", box=DOUBLE)
    table.add_column("Service", style="cyan")
    table.add_column("Zero-Day Score (0-10)", style="yellow")
    table.add_column("Risk Factors", style="green")
    
    for pred in predictions:
        factors = f"CVE Count: {pred['cve_count']}, Age: {pred['age_risk']}, Complexity: {pred['complexity']}, Port: {pred['port_usage']}"
        table.add_row(pred['service'], str(pred['zero_day_score']), factors)
    
    console.print(table)
    
    # Step 5: Save report
    report_file = os.path.join(OUTPUT_DIR, f"zeroday_{target}.json")
    with open(report_file, "w") as f:
        json.dump(predictions, f, indent=4)
    
    console.print(f"[green]Zero-day prediction completed. Report saved to: {report_file}[/green]")
    logger.info(f"Zero-day prediction completed for {target}. Found {len(predictions)} potential risks.")

# Update display_menu() function - replace the existing one with this:
def display_menu():
    layout = create_dashboard()
    menu_table = Table(title="Select a Task", show_header=False, expand=True, box=DOUBLE)
    menu_items = [
        "[green][1][/green] System Metrics Monitoring - Real-time with anomaly detection",
        "[green][2][/green] Security Testing - Simulated attacks with packet crafting",
        "[green][3][/green] Remote Reconnaissance - SSH-based with encrypted creds",
        "[green][4][/green] Network Scanning - Vulnerability scoring and visualization",
        "[green][5][/green] Auth Log Analyzer - With threat intelligence lookup",
        "[green][6][/green] DNS Enumeration - With spoofing detection",
        "[green][7][/green] Firewall Rule Auditor - Analyze and suggest rules",
        "[green][8][/green] Wi-Fi Security Scanner - Assess wireless networks",
        "[green][9][/green] Intrusion Detection - Real-time packet monitoring",
        "[green][10][/green] DDoS Mitigation - Simulate and mitigate",
        "[green][11][/green] Advanced Network Protocol Analyzer",
        "[green][12][/green] Malware Analysis Lab",
        "[green][13][/green] Web Application Security Scanner",
        "[green][14][/green] Memory Forensics Analyzer",
        "[green][15][/green] Binary Analysis Tool",
        "[green][16][/green] Automated OSINT Collection - Web, WHOIS, Shodan",
        "[green][17][/green] SSL/TLS Security Auditor - Certs and ciphers",
        "[green][18][/green] Automated Phishing Detection - Email/URL analysis",
        "[green][19][/green] Dark Web Scanner - Onion network search",
        "[green][20][/green] Automated Exploit Framework - Vulnerability exploitation",
        "[green][21][/green] Synthetic Attack Generator - Multi-type attack simulation",
        "[green][22][/green] Advanced Packet Forensics - PCAP deep dive",
        "[green][23][/green] GeoIP Threat Mapping - Location-based threat intel",
        "[green][24][/green] SOC Automation Dashboard - Real-time threat monitoring",
        "[green][25][/green] Automated Honeypot Deployer - Trap attackers",
        "[green][26][/green] Network Device Scanner - List devices with IPs and MACs",
        "[green][27][/green] Zero-Day Predictor - ML-inspired vulnerability prediction",
        "[green][0][/green] Exit - Quit the toolkit"
    ]
    for item in menu_items:
        menu_table.add_row(item)
    layout["actions"].update(menu_table)
    
    console.print(layout)
    return Prompt.ask("Enter your choice (0-27)", choices=[str(i) for i in range(28)])

# Update main() function - add this case before "elif choice == '0':"
def main():
    display_banner()
    check_dependencies()
    init_db()
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
            elif choice == "16":
                asyncio.run(osint_collection())
            elif choice == "17":
                ssl_auditor()
            elif choice == "18":
                phishing_detection()
            elif choice == "19":
                asyncio.run(dark_web_scanner())
            elif choice == "20":
                exploit_framework()
            elif choice == "21":
                synthetic_attack_generator()
            elif choice == "22":
                packet_forensics()
            elif choice == "23":
                geoip_threat_mapping()
            elif choice == "24":
                soc_automation()
            elif choice == "25":
                honeypot_deployer()
            elif choice == "26":
                network_devices()
            elif choice == "27":
                zero_day_predictor()
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

# Add missing create_dashboard() function that was referenced
def create_dashboard():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main")
    )
    layout["header"].update(Panel("[cyan]CyberSec Toolkit 2025[/cyan]", border_style="green"))
    layout["main"].split_row(
        Layout(name="actions", ratio=1)
    )
    return layout

# Add missing import at the top with other imports
from ipaddress import ip_network

if __name__ == "__main__":
    main()