#!/bin/bash
#########################################################################
# Student Name: Your Name Here
# Student Code: Your Student Code Here
# Class Code: NX201
# Lecturer Name: Your Lecturer Name Here
# Project: REMOTE CONTROL
#########################################################################
# This script automates the connection to a remote server and executes
# reconnaissance commands while maintaining anonymity. It checks for
# required dependencies, verifies anonymous connection, and performs
# target scanning via the remote server.
#########################################################################

# Text colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file path
LOG_FILE="reconnaissance_audit.log"
WHOIS_OUTPUT="target_whois.txt"
NMAP_OUTPUT="target_nmap.txt"

# Remote server credentials (these would be provided in a real scenario)
REMOTE_SERVER="remote_server_ip"
REMOTE_USER="remote_username"
REMOTE_PASS="remote_password"

#########################################################################
# Function: log_message
# Description: Logs messages to the audit file with timestamp
#########################################################################
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo -e "${BLUE}[INFO]${NC} $1"
}

#########################################################################
# Function: check_dependencies
# Description: Checks and installs required dependencies if not present
#########################################################################
check_dependencies() {
    log_message "Checking for required dependencies..."
    
    dependencies=("sshpass" "tor" "nipe" "nmap" "whois")
    
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_message "$dep is not installed. Installing now..."
            
            case "$dep" in
                "sshpass")
                    sudo apt-get install -y sshpass
                    ;;
                "tor")
                    sudo apt-get install -y tor
                    ;;
                "nipe")
                    if [ ! -d "nipe" ]; then
                        log_message "Cloning nipe repository..."
                        git clone https://github.com/htrgouvea/nipe
                        cd nipe
                        sudo cpan install Try::Tiny Config::Simple JSON
                        sudo perl nipe.pl install
                        cd ..
                    else
                        log_message "Nipe directory already exists. Skipping installation."
                    fi
                    ;;
                "nmap")
                    sudo apt-get install -y nmap
                    ;;
                "whois")
                    sudo apt-get install -y whois
                    ;;
            esac
        else
            log_message "$dep is already installed."
        fi
    done
    
    log_message "All dependencies are installed."
}

#########################################################################
# Function: check_anonymity
# Description: Checks if the connection is anonymous using nipe
#########################################################################
check_anonymity() {
    log_message "Checking network anonymity status..."
    
    # Start nipe if not already running
    cd nipe
    sudo perl nipe.pl start
    
    # Check if nipe is running and the connection is anonymous
    anonymity_status=$(sudo perl nipe.pl status | grep -i "activated" | wc -l)
    
    if [ "$anonymity_status" -eq 1 ]; then
        # Get spoofed country information
        country=$(curl -s ipinfo.io | jq -r .country)
        log_message "Connection is anonymous. Spoofed country: $country"
        cd ..
        return 0
    else
        log_message "Connection is NOT anonymous! Attempting to restart nipe..."
        sudo perl nipe.pl restart
        
        # Check again after restart
        anonymity_status=$(sudo perl nipe.pl status | grep -i "activated" | wc -l)
        
        if [ "$anonymity_status" -eq 1 ]; then
            country=$(curl -s ipinfo.io | jq -r .country)
            log_message "Connection is now anonymous. Spoofed country: $country"
            cd ..
            return 0
        else
            log_message "Failed to establish anonymous connection. Exiting for security."
            cd ..
            return 1
        fi
    fi
}

#########################################################################
# Function: get_target_address
# Description: Gets the target address from the user
#########################################################################
get_target_address() {
    echo -e "${YELLOW}Enter the target address to scan:${NC}"
    read -r target_address
    
    # Validate input (basic check)
    if [[ -z "$target_address" ]]; then
        echo -e "${RED}Error: Target address cannot be empty.${NC}"
        get_target_address
    else
        log_message "Target address set to: $target_address"
    fi
    
    echo "$target_address"
}

#########################################################################
# Function: connect_to_remote_server
# Description: Connects to the remote server and gets its details
#########################################################################
connect_to_remote_server() {
    log_message "Connecting to remote server..."
    
    # Get server details
    server_details=$(sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_SERVER" \
                    "echo 'Country: '\$(curl -s ipinfo.io | jq -r .country); \
                     echo 'IP: '\$(curl -s ipinfo.io | jq -r .ip); \
                     echo 'Uptime: '\$(uptime -p)")
    
    echo -e "${GREEN}Remote Server Details:${NC}"
    echo "$server_details"
    log_message "Successfully connected to remote server"
    log_message "Server details: $(echo "$server_details" | tr '\n' ' ')"
}

#########################################################################
# Function: execute_whois
# Description: Executes Whois lookup on the target via remote server
#########################################################################
execute_whois() {
    local target=$1
    log_message "Executing Whois lookup on $target via remote server..."
    
    whois_data=$(sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_SERVER" \
                "whois $target")
    
    echo "$whois_data" > "$WHOIS_OUTPUT"
    log_message "Whois data saved to $WHOIS_OUTPUT"
    
    return 0
}

#########################################################################
# Function: execute_nmap
# Description: Executes Nmap scan on the target via remote server
#########################################################################
execute_nmap() {
    local target=$1
    log_message "Executing Nmap scan on $target via remote server..."
    
    nmap_data=$(sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_SERVER" \
               "nmap -sS -T4 $target")
    
    echo "$nmap_data" > "$NMAP_OUTPUT"
    log_message "Nmap scan data saved to $NMAP_OUTPUT"
    
    return 0
}

#########################################################################
# Main Function
#########################################################################
main() {
    # Clear terminal
    clear
    
    # Display banner
    echo -e "${GREEN}========================================================${NC}"
    echo -e "${GREEN}                 REMOTE CONTROL TOOL                    ${NC}"
    echo -e "${GREEN}                  PROJECT: NX201                        ${NC}"
    echo -e "${GREEN}========================================================${NC}"
    
    # Initialize log file
    echo "=== RECONNAISSANCE AUDIT LOG ===" > "$LOG_FILE"
    echo "Started at: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
    
    # 1. Check and install dependencies
    check_dependencies
    
    # 2. Check anonymity
    if ! check_anonymity; then
        echo -e "${RED}ERROR: Anonymous connection could not be established. Exiting for security.${NC}"
        log_message "CRITICAL: Script terminated due to non-anonymous connection"
        exit 1
    fi
    
    # 3. Get target address from user
    target_address=$(get_target_address)
    
    # 4. Connect to remote server and display its details
    connect_to_remote_server
    
    # 5. Execute Whois lookup via remote server
    execute_whois "$target_address"
    
    # 6. Execute Nmap scan via remote server
    execute_nmap "$target_address"
    
    # 7. Display completion message
    echo -e "${GREEN}========================================================${NC}"
    echo -e "${GREEN}         Reconnaissance completed successfully!          ${NC}"
    echo -e "${GREEN}  Whois data saved to: ${YELLOW}$WHOIS_OUTPUT${NC}"
    echo -e "${GREEN}  Nmap data saved to: ${YELLOW}$NMAP_OUTPUT${NC}"
    echo -e "${GREEN}  Audit log saved to: ${YELLOW}$LOG_FILE${NC}"
    echo -e "${GREEN}========================================================${NC}"
    
    log_message "Script execution completed successfully"
    echo "Ended at: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
}

# Execute main function
main
