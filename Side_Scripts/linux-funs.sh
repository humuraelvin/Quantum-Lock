#!/bin/bash
#########################################################################
# Student Name: Your Name Here
# Student Code: Your Student Code Here
# Class Code: LINUX FUNDAMENTALS
# Lecturer Name: Your Lecturer Name Here
# Project: SYSTEM METRICS MONITOR
#########################################################################
# This script monitors and displays various system metrics including:
# - Network details (private IP, public IP, default gateway)
# - Disk statistics (total, used, and free space)
# - The five largest directories
# - Real-time CPU usage (updated every 10 seconds)
#########################################################################

# Text colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to clear the screen and display header
display_header() {
    clear
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${GREEN}       LINUX SYSTEM METRICS MONITOR             ${NC}"
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${YELLOW}Last Updated: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${GREEN}=================================================${NC}"
    echo ""
}

# Function to get network details
get_network_details() {
    echo -e "${CYAN}NETWORK DETAILS:${NC}"
    echo -e "${CYAN}----------------${NC}"
    
    # Get private IP address
    private_ip=$(hostname -I | awk '{print $1}')
    echo -e "${BLUE}Private IP Address:${NC} $private_ip"
    
    # Get public IP address using an external service
    echo -e "${BLUE}Public IP Address:${NC} $(curl -s ifconfig.me)"
    
    # Get default gateway
    default_gateway=$(ip route | grep default | awk '{print $3}')
    echo -e "${BLUE}Default Gateway:${NC} $default_gateway"
    
    echo ""
}

# Function to get disk statistics
get_disk_stats() {
    echo -e "${CYAN}DISK STATISTICS:${NC}"
    echo -e "${CYAN}----------------${NC}"
    
    # Get disk usage statistics
    echo -e "${BLUE}Disk Usage:${NC}"
    df -h / | grep -v Filesystem | awk '{print "Total: " $2 "  Used: " $3 "  Free: " $4 "  Use%: " $5}'
    
    echo ""
}

# Function to find the five largest directories
find_largest_dirs() {
    echo -e "${CYAN}FIVE LARGEST DIRECTORIES:${NC}"
    echo -e "${CYAN}------------------------${NC}"
    
    echo -e "${YELLOW}Searching for largest directories (this may take a moment)...${NC}"
    echo -e "${BLUE}Size\tPath${NC}"
    
    # Find largest directories in the root filesystem, excluding mounted filesystems
    # We exclude certain system directories to avoid permission issues
    du -hx --max-depth=3 / 2>/dev/null | sort -rh | head -5 | awk '{print $1 "\t" $2}'
    
    echo ""
}

# Function to get and display CPU usage
get_cpu_usage() {
    echo -e "${CYAN}CPU USAGE:${NC}"
    echo -e "${CYAN}----------${NC}"
    
    # Get the CPU usage using top command for a brief period
    echo -e "${BLUE}Current CPU Usage:${NC}"
    top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4 "% used, " $6 + $8 + $10 "% idle"}'
    
    # Additional CPU info from /proc/stat
    echo -e "${BLUE}CPU Load Averages:${NC} $(uptime | awk -F'load average:' '{print $2}')"
    
    echo ""
}

# Function to get memory usage
get_memory_usage() {
    echo -e "${CYAN}MEMORY USAGE:${NC}"
    echo -e "${CYAN}-------------${NC}"
    
    # Get memory usage statistics
    echo -e "${BLUE}Memory Statistics:${NC}"
    free -h | grep Mem | awk '{print "Total: " $2 "  Used: " $3 "  Free: " $4 "  Shared: " $5 "  Buff/Cache: " $6 "  Available: " $7}'
    
    echo ""
}

# Function to get system uptime
get_system_uptime() {
    echo -e "${CYAN}SYSTEM UPTIME:${NC}"
    echo -e "${CYAN}-------------${NC}"
    
    # Get system uptime
    uptime_info=$(uptime -p)
    echo -e "${BLUE}$uptime_info${NC}"
    
    echo ""
}

# Main function to run the monitoring script
main() {
    while true; do
        display_header
        get_network_details
        get_disk_stats
        get_memory_usage
        get_cpu_usage
        find_largest_dirs
        get_system_uptime
        
        echo -e "${YELLOW}Updates every 10 seconds. Press Ctrl+C to exit.${NC}"
        sleep 10
    done
}

# Execute the main function
main
