#!/bin/bash

###########################################
# SOC Analyst Project: CHECKER
# Program Code: NX220
# 
# This script implements an automatic attack system for SOC team testing.
# It allows SOC managers to choose different types of attacks,
# execute them against specified targets, and log the activities.
#
# Author: SOC Analyst Student
# Class Code: NX220
# Lecturer: ThinkCyber Instructor
###########################################

# Color codes for better visual output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Log file path
LOG_FILE="/var/log/soc_checker.log"

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: This script must be run as root${NC}"
  exit 1
fi

# Create log file if it doesn't exist
if [ ! -f "$LOG_FILE" ]; then
  touch "$LOG_FILE"
  chmod 644 "$LOG_FILE"
  echo -e "${GREEN}Log file created at $LOG_FILE${NC}"
fi

# Function to log activities
log_activity() {
  local attack_type="$1"
  local target_ip="$2"
  local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
  
  echo "[$timestamp] Attack Type: $attack_type | Target: $target_ip" >> "$LOG_FILE"
  echo -e "${GREEN}Activity logged successfully${NC}"
}

# Function to display banner
display_banner() {
  clear
  echo -e "${BLUE}=========================================================${NC}"
  echo -e "${CYAN}               SOC ANALYST - PROJECT: CHECKER           ${NC}"
  echo -e "${CYAN}                    Program Code: NX220                 ${NC}"
  echo -e "${BLUE}=========================================================${NC}"
  echo -e "${YELLOW}This tool is for educational and authorized testing ONLY.${NC}"
  echo -e "${YELLOW}Unauthorized use against systems without permission is illegal.${NC}"
  echo -e "${BLUE}=========================================================${NC}"
  echo ""
}

# Function to scan for available IP addresses on the network
scan_network() {
  echo -e "${CYAN}Scanning for available IP addresses on the network...${NC}"
  echo -e "${YELLOW}This may take a moment...${NC}"
  
  # Get the local IP address and subnet
  local_ip=$(hostname -I | awk '{print $1}')
  subnet=$(echo $local_ip | cut -d. -f1-3)
  
  # Use nmap to scan the local network
  echo -e "${PURPLE}Scanning subnet $subnet.0/24...${NC}"
  
  # Store scan results in an array
  mapfile -t available_ips < <(nmap -sn $subnet.0/24 | grep "Nmap scan report" | awk '{print $NF}' | tr -d '()')
  
  echo -e "${GREEN}Scan completed. Found ${#available_ips[@]} active IP addresses.${NC}"
  return 0
}

# Function to display available IP addresses
display_ips() {
  echo -e "${CYAN}Available IP addresses:${NC}"
  for i in "${!available_ips[@]}"; do
    echo -e "${GREEN}[$i] ${available_ips[$i]}${NC}"
  done
  echo ""
}

# Function for Port Scanning Attack (using nmap)
port_scan_attack() {
  local target_ip="$1"
  
  echo -e "${CYAN}Performing Port Scanning attack against ${target_ip}...${NC}"
  echo -e "${YELLOW}Running nmap scan...${NC}"
  
  # Execute the port scan
  nmap -sS -p 1-1000 "$target_ip"
  
  echo -e "${GREEN}Port Scanning attack completed.${NC}"
  
  # Log the activity
  log_activity "Port Scanning" "$target_ip"
}

# Function for Brute Force Attack (using hydra)
brute_force_attack() {
  local target_ip="$1"
  
  echo -e "${CYAN}Performing Brute Force attack simulation against ${target_ip}...${NC}"
  echo -e "${YELLOW}Note: This is a simulated attack for demonstration purposes.${NC}"
  
  # Simulating Hydra command (not actually executing brute force)
  echo -e "${PURPLE}Command that would be executed: hydra -l admin -P /usr/share/wordlists/rockyou.txt ${target_ip} ssh${NC}"
  
  # Simulate attack output
  echo "Hydra v9.1 (c) 2020 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes."
  echo "Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at $(date)"
  echo "SIMULATION MODE - NO ACTUAL CONNECTION ATTEMPTS MADE"
  echo "[SIMULATION] target ${target_ip} - 16 of 14344384 [child 0] (0/0)"
  echo "[SIMULATION] target ${target_ip} - 28 of 14344384 [child 1] (0/0)"
  sleep 2
  echo "[SIMULATION] 1 of 1 target completed, 0 valid passwords found"
  
  echo -e "${GREEN}Brute Force attack simulation completed.${NC}"
  
  # Log the activity
  log_activity "Brute Force Simulation" "$target_ip"
}

# Function for DoS Attack Simulation (using hping3)
dos_attack_simulation() {
  local target_ip="$1"
  
  echo -e "${CYAN}Performing DoS attack simulation against ${target_ip}...${NC}"
  echo -e "${YELLOW}Note: This is a simulated attack for educational purposes only.${NC}"
  
  # Show command that would be executed (without actually running a DoS)
  echo -e "${PURPLE}Command that would be executed: hping3 --flood -S -p 80 ${target_ip}${NC}"
  
  # Simulate attack output
  echo "HPING ${target_ip} (eth0 ${target_ip}): S set, 40 headers + 0 data bytes"
  echo "SIMULATION MODE - NO ACTUAL PACKETS SENT"
  echo "--- ${target_ip} hping statistic ---"
  echo "10000 packets transmitted, 9800 packets received, 2% packet loss"
  echo "round-trip min/avg/max = 0.1/2.5/10.3 ms"
  
  echo -e "${GREEN}DoS attack simulation completed.${NC}"
  
  # Log the activity
  log_activity "DoS Attack Simulation" "$target_ip"
}

# Function for ARP Spoofing Attack (using arpspoof)
arp_spoofing_attack() {
  local target_ip="$1"
  
  echo -e "${CYAN}Performing ARP Spoofing attack simulation against ${target_ip}...${NC}"
  echo -e "${YELLOW}Note: This is a simulated attack for educational purposes only.${NC}"
  
  # Get default gateway
  gateway=$(ip route | grep default | awk '{print $3}')
  
  # Show command that would be executed
  echo -e "${PURPLE}Command that would be executed: arpspoof -i eth0 -t ${target_ip} ${gateway}${NC}"
  
  # Simulate attack output
  echo "SIMULATION MODE - NO ACTUAL ARP SPOOFING PERFORMED"
  echo "0:c:29:af:23:92 0:1:2:3:4:5 0806 42: arp reply ${gateway} is-at 0:c:29:af:23:92"
  echo "0:c:29:af:23:92 0:1:2:3:4:5 0806 42: arp reply ${gateway} is-at 0:c:29:af:23:92"
  sleep 1
  echo "0:c:29:af:23:92 0:1:2:3:4:5 0806 42: arp reply ${gateway} is-at 0:c:29:af:23:92"
  
  echo -e "${GREEN}ARP Spoofing simulation completed.${NC}"
  
  # Log the activity
  log_activity "ARP Spoofing Simulation" "$target_ip"
}

# Function to display attack descriptions
display_attack_descriptions() {
  echo -e "${CYAN}Available Attacks:${NC}"
  echo -e "${GREEN}[1] Port Scanning${NC}"
  echo -e "    Description: Scans the target system for open ports to identify services running."
  echo -e "    Tool: Nmap"
  echo ""
  
  echo -e "${GREEN}[2] Brute Force Attack Simulation${NC}"
  echo -e "    Description: Simulates a brute force password attack against SSH service."
  echo -e "    Tool: Hydra (simulation only)"
  echo ""
  
  echo -e "${GREEN}[3] DoS Attack Simulation${NC}"
  echo -e "    Description: Simulates a Denial of Service attack by flooding the target with TCP packets."
  echo -e "    Tool: Hping3 (simulation only)"
  echo ""
  
  echo -e "${GREEN}[4] ARP Spoofing Simulation${NC}"
  echo -e "    Description: Simulates an ARP poisoning attack to intercept network traffic."
  echo -e "    Tool: Arpspoof (simulation only)"
  echo ""
  
  echo -e "${GREEN}[0] Random Attack${NC}"
  echo -e "    Description: Selects one of the above attacks randomly."
  echo ""
}

# Main function
main() {
  display_banner
  
  # Check for required tools
  for tool in nmap hydra hping3 arpspoof; do
    if ! command -v $tool &> /dev/null; then
      echo -e "${RED}Error: Required tool '$tool' is not installed.${NC}"
      echo -e "${YELLOW}Please install it using: apt-get install $tool${NC}"
      exit 1
    fi
  done
  
  # Scan for available IP addresses
  scan_network
  
  if [ ${#available_ips[@]} -eq 0 ]; then
    echo -e "${RED}Error: No IP addresses found on the network. Exiting.${NC}"
    exit 1
  fi
  
  # Display available IP addresses
  display_ips
  
  # Display attack descriptions
  display_attack_descriptions
  
  # Ask user to select an attack
  echo -e "${CYAN}Select an attack (0-4):${NC}"
  read attack_choice
  
  # Validate attack choice
  if ! [[ "$attack_choice" =~ ^[0-4]$ ]]; then
    echo -e "${RED}Error: Invalid attack choice. Exiting.${NC}"
    exit 1
  fi
  
  # If random attack is selected
  if [ "$attack_choice" -eq 0 ]; then
    attack_choice=$((1 + RANDOM % 4))
    echo -e "${GREEN}Randomly selected attack: $attack_choice${NC}"
  fi
  
  # Ask user to select a target IP
  echo -e "${CYAN}Select a target IP by number, or enter 'r' for random target:${NC}"
  read ip_choice
  
  # Handle random IP selection
  if [ "$ip_choice" = "r" ]; then
    ip_index=$((RANDOM % ${#available_ips[@]}))
    target_ip=${available_ips[$ip_index]}
    echo -e "${GREEN}Randomly selected target IP: $target_ip${NC}"
  # Validate IP choice
  elif [[ "$ip_choice" =~ ^[0-9]+$ ]] && [ "$ip_choice" -lt ${#available_ips[@]} ]; then
    target_ip=${available_ips[$ip_choice]}
  else
    echo -e "${RED}Error: Invalid IP selection. Exiting.${NC}"
    exit 1
  fi
  
  # Execute the selected attack
  echo -e "${CYAN}Executing attack against $target_ip...${NC}"
  echo -e "${YELLOW}Press Ctrl+C to abort at any time.${NC}"
  
  # Wait for confirmation before proceeding
  echo -e "${RED}WARNING: This is a security testing tool. Only use against authorized targets.${NC}"
  echo -e "${CYAN}Press Enter to continue or Ctrl+C to abort...${NC}"
  read
  
  case "$attack_choice" in
    1) port_scan_attack "$target_ip" ;;
    2) brute_force_attack "$target_ip" ;;
    3) dos_attack_simulation "$target_ip" ;;
    4) arp_spoofing_attack "$target_ip" ;;
    *) echo -e "${RED}Invalid attack selected. Exiting.${NC}"; exit 1 ;;
  esac
  
  echo -e "${GREEN}Attack completed. Check logs at $LOG_FILE${NC}"
}

# Run the main function
main
