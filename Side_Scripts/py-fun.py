#!/usr/bin/env python3
"""
Auth.log Analysis Tool

This script analyzes /var/log/auth.log files to extract valuable security insights,
track user authentication events, and identify potential security anomalies.

Usage:
    python auth_log_analyzer.py [path_to_log_file]

If no path is provided, the script will attempt to analyze /var/log/auth.log.
"""

import sys
import re
import os
from collections import defaultdict, Counter
from datetime import datetime
import argparse
import ipaddress

class AuthLogAnalyzer:
    """
    A class to analyze authentication log files and extract security insights.
    
    This analyzer focuses on:
    - Failed login attempts and patterns
    - User authentication changes
    - Sudo command usage
    - Unusual login times or locations
    - Potential brute force attacks
    """
    
    def __init__(self, log_file='/var/log/auth.log'):
        """
        Initialize the analyzer with the path to the log file.
        
        Args:
            log_file (str): Path to the auth.log file
        """
        self.log_file = log_file
        self.log_entries = []
        self.failed_logins = defaultdict(list)
        self.successful_logins = defaultdict(list)
        self.sudo_usage = defaultdict(list)
        self.user_creations = []
        self.password_changes = []
        self.permission_changes = []
        self.ip_addresses = defaultdict(list)
        self.unusual_events = []
        
    def load_log_file(self):
        """
        Loads and parses the log file.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not os.path.exists(self.log_file):
                print(f"Error: Log file {self.log_file} does not exist.")
                return False
                
            with open(self.log_file, 'r', errors='replace') as file:
                self.log_entries = file.readlines()
            return True
        except Exception as e:
            print(f"Error loading log file: {e}")
            return False
    
    def parse_timestamp(self, timestamp_str):
        """
        Parses a log timestamp into a datetime object.
        
        Args:
            timestamp_str (str): The timestamp string from the log
            
        Returns:
            datetime: A datetime object representing the timestamp
        """
        # Example format: Mar 15 06:47:31
        current_year = datetime.now().year
        try:
            dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            # Add the current year since auth.log doesn't include it
            return dt.replace(year=current_year)
        except ValueError:
            # If there's an issue with parsing, return current time
            return datetime.now()
    
    def analyze_logs(self):
        """
        Analyzes the log entries to extract security-relevant information.
        """
        if not self.log_entries:
            print("No log entries to analyze. Please load the log file first.")
            return
        
        # Regular expressions for different types of events
        failed_login_pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\w+) from (\S+)')
        successful_login_pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\w+) from (\S+)')
        sudo_pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+).*sudo:.*user=(\w+).*command=(.*)')
        user_creation_pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+).*new user:.*name=(\w+)')
        password_change_pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+).*password changed for (\w+)')
        permission_change_pattern = re.compile(r'(\w+\s+\d+\s+\d+:\d+:\d+).*usermod.*for (\w+)')
        
        for entry in self.log_entries:
            # Check for failed login attempts
            match = failed_login_pattern.search(entry)
            if match:
                timestamp, username, ip = match.groups()
                dt = self.parse_timestamp(timestamp)
                self.failed_logins[username].append((dt, ip))
                self.ip_addresses[ip].append(("failed_login", username, dt))
                continue
                
            # Check for successful logins
            match = successful_login_pattern.search(entry)
            if match:
                timestamp, username, ip = match.groups()
                dt = self.parse_timestamp(timestamp)
                self.successful_logins[username].append((dt, ip))
                self.ip_addresses[ip].append(("successful_login", username, dt))
                continue
                
            # Check for sudo usage
            match = sudo_pattern.search(entry)
            if match:
                timestamp, username, command = match.groups()
                dt = self.parse_timestamp(timestamp)
                self.sudo_usage[username].append((dt, command))
                continue
                
            # Check for user creations
            match = user_creation_pattern.search(entry)
            if match:
                timestamp, username = match.groups()
                dt = self.parse_timestamp(timestamp)
                self.user_creations.append((dt, username))
                continue
                
            # Check for password changes
            match = password_change_pattern.search(entry)
            if match:
                timestamp, username = match.groups()
                dt = self.parse_timestamp(timestamp)
                self.password_changes.append((dt, username))
                continue
                
            # Check for permission changes
            match = permission_change_pattern.search(entry)
            if match:
                timestamp, username = match.groups()
                dt = self.parse_timestamp(timestamp)
                self.permission_changes.append((dt, username))
                continue
                
            # Check for any unusual patterns or keywords
            if any(keyword in entry.lower() for keyword in ["warning", "error", "alert", "critical", "exploit", "attack"]):
                self.unusual_events.append(entry)
    
    def detect_brute_force(self, threshold=5, time_window_minutes=10):
        """
        Detects potential brute force attacks based on failed login attempts.
        
        Args:
            threshold (int): Number of failed attempts to consider as suspicious
            time_window_minutes (int): Time window in minutes to check for attempts
            
        Returns:
            dict: Dictionary of potential brute force attacks by IP
        """
        potential_attacks = defaultdict(list)
        
        # Group failed logins by IP address
        ip_failures = defaultdict(list)
        for username, attempts in self.failed_logins.items():
            for dt, ip in attempts:
                ip_failures[ip].append((dt, username))
        
        # Identify potential brute force attacks
        for ip, attempts in ip_failures.items():
            # Sort attempts by timestamp
            sorted_attempts = sorted(attempts, key=lambda x: x[0])
            
            # Check for clusters of attempts within the time window
            if len(sorted_attempts) >= threshold:
                for i in range(len(sorted_attempts) - threshold + 1):
                    start_time = sorted_attempts[i][0]
                    end_time = sorted_attempts[i + threshold - 1][0]
                    time_diff = (end_time - start_time).total_seconds() / 60
                    
                    if time_diff <= time_window_minutes:
                        # Extract usernames targeted in this window
                        usernames = [attempt[1] for attempt in sorted_attempts[i:i+threshold]]
                        potential_attacks[ip].append({
                            'start_time': start_time,
                            'end_time': end_time,
                            'attempts': threshold,
                            'usernames': usernames
                        })
                        break  # Found one instance for this IP, move to next IP
        
        return potential_attacks
    
    def detect_privilege_escalation(self):
        """
        Detects potential privilege escalation attempts.
        
        Returns:
            list: List of potential privilege escalation events
        """
        privilege_escalation = []
        
        # Look for patterns indicating privilege escalation
        sudo_sensitive_commands = [
            "sudo", "su", "usermod", "chmod", "chown", 
            "passwd", "visudo", "useradd", "groupadd"
        ]
        
        for username, commands in self.sudo_usage.items():
            for dt, command in commands:
                if any(cmd in command for cmd in sudo_sensitive_commands):
                    # Check if this user normally uses these commands
                    if len([c for _, c in commands if any(cmd in c for cmd in sudo_sensitive_commands)]) <= 2:
                        privilege_escalation.append({
                            'timestamp': dt,
                            'username': username,
                            'command': command,
                            'reason': 'Unusual privileged command'
                        })
        
        return privilege_escalation
    
    def detect_unusual_login_times(self, start_hour=23, end_hour=5):
        """
        Detects logins occurring during unusual hours.
        
        Args:
            start_hour (int): Start hour of the unusual time window (24h format)
            end_hour (int): End hour of the unusual time window (24h format)
            
        Returns:
            list: List of unusual login events
        """
        unusual_logins = []
        
        for username, logins in self.successful_logins.items():
            for dt, ip in logins:
                hour = dt.hour
                # Check if login occurred during unusual hours
                if start_hour <= hour or hour <= end_hour:
                    unusual_logins.append({
                        'timestamp': dt,
                        'username': username,
                        'ip': ip,
                        'hour': hour
                    })
        
        return unusual_logins
    
    def get_login_statistics(self):
        """
        Generates statistics about login attempts.
        
        Returns:
            dict: Dictionary with login statistics
        """
        stats = {
            'total_failed_attempts': sum(len(attempts) for attempts in self.failed_logins.values()),
            'total_successful_logins': sum(len(logins) for logins in self.successful_logins.values()),
            'users_with_failed_attempts': len(self.failed_logins),
            'users_with_successful_logins': len(self.successful_logins),
            'most_targeted_users': Counter({user: len(attempts) for user, attempts in self.failed_logins.items()}).most_common(5),
            'most_active_users': Counter({user: len(logins) for user, logins in self.successful_logins.items()}).most_common(5),
            'most_active_ips': Counter({ip: len(events) for ip, events in self.ip_addresses.items()}).most_common(5)
        }
        
        return stats
    
    def analyze_ip_addresses(self):
        """
        Analyzes IP addresses for geographical distribution and other patterns.
        
        Returns:
            dict: Dictionary with IP analysis results
        """
        ip_analysis = {
            'total_unique_ips': len(self.ip_addresses),
            'ips_by_activity': defaultdict(list),
            'internal_vs_external': {'internal': 0, 'external': 0},
            'ip_countries': defaultdict(int)  # Would require GeoIP lookup
        }
        
        for ip in self.ip_addresses:
            try:
                ip_obj = ipaddress.ip_address(ip)
                
                # Classify as internal or external IP
                if ip_obj.is_private:
                    ip_analysis['internal_vs_external']['internal'] += 1
                else:
                    ip_analysis['internal_vs_external']['external'] += 1
                
                # Group IPs by activity type
                activities = set(event[0] for event in self.ip_addresses[ip])
                for activity in activities:
                    ip_analysis['ips_by_activity'][activity].append(ip)
                
            except ValueError:
                # Not a valid IP address, might be a hostname
                ip_analysis['internal_vs_external']['external'] += 1
        
        return ip_analysis
    
    def generate_report(self):
        """
        Generates a comprehensive security report based on the log analysis.
        
        Returns:
            dict: Dictionary containing the full analysis report
        """
        # Ensure logs have been analyzed
        if not hasattr(self, 'failed_logins') or not self.failed_logins:
            print("No analysis data available. Please run analyze_logs() first.")
            return {}
        
        # Generate the full report
        report = {
            'summary': {
                'log_file': self.log_file,
                'entries_analyzed': len(self.log_entries),
                'analysis_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            'login_statistics': self.get_login_statistics(),
            'potential_brute_force': self.detect_brute_force(),
            'privilege_escalation': self.detect_privilege_escalation(),
            'unusual_login_times': self.detect_unusual_login_times(),
            'ip_analysis': self.analyze_ip_addresses(),
            'user_account_changes': {
                'user_creations': self.user_creations,
                'password_changes': self.password_changes,
                'permission_changes': self.permission_changes
            },
            'sudo_command_usage': {user: len(cmds) for user, cmds in self.sudo_usage.items()},
            'unusual_events': len(self.unusual_events)
        }
        
        return report
    
    def print_report(self, report=None):
        """
        Prints a human-readable version of the security report.
        
        Args:
            report (dict, optional): Report to print. If None, generates a new report.
        """
        if report is None:
            report = self.generate_report()
        
        if not report:
            return
        
        print("\n" + "="*80)
        print(f"AUTH.LOG SECURITY ANALYSIS REPORT")
        print(f"Log File: {report['summary']['log_file']}")
        print(f"Analysis Time: {report['summary']['analysis_time']}")
        print(f"Entries Analyzed: {report['summary']['entries_analyzed']}")
        print("="*80 + "\n")
        
        # Login Statistics
        stats = report['login_statistics']
        print("LOGIN STATISTICS:")
        print(f"- Total Failed Attempts: {stats['total_failed_attempts']}")
        print(f"- Total Successful Logins: {stats['total_successful_logins']}")
        print(f"- Users with Failed Attempts: {stats['users_with_failed_attempts']}")
        print(f"- Users with Successful Logins: {stats['users_with_successful_logins']}")
        
        print("\nMost Targeted Users (Failed Logins):")
        for user, count in stats['most_targeted_users']:
            print(f"  - {user}: {count} attempts")
        
        print("\nMost Active Users (Successful Logins):")
        for user, count in stats['most_active_users']:
            print(f"  - {user}: {count} logins")
        
        print("\nMost Active IP Addresses:")
        for ip, count in stats['most_active_ips']:
            print(f"  - {ip}: {count} events")
        
        # Potential Brute Force Attacks
        print("\nPOTENTIAL BRUTE FORCE ATTACKS:")
        if report['potential_brute_force']:
            for ip, attacks in report['potential_brute_force'].items():
                for attack in attacks:
                    print(f"- IP: {ip}")
                    print(f"  Start Time: {attack['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"  End Time: {attack['end_time'].strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"  Attempts: {attack['attempts']}")
                    print(f"  Targeted Users: {', '.join(set(attack['usernames']))}")
                    print("")
        else:
            print("- No potential brute force attacks detected")
        
        # Privilege Escalation
        print("\nPOTENTIAL PRIVILEGE ESCALATION:")
        if report['privilege_escalation']:
            for event in report['privilege_escalation']:
                print(f"- User: {event['username']}")
                print(f"  Timestamp: {event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"  Command: {event['command']}")
                print(f"  Reason: {event['reason']}")
                print("")
        else:
            print("- No potential privilege escalation events detected")
        
        # Unusual Login Times
        print("\nUNUSUAL LOGIN TIMES:")
        if report['unusual_login_times']:
            for login in report['unusual_login_times'][:5]:  # Show first 5 for brevity
                print(f"- User: {login['username']}")
                print(f"  Timestamp: {login['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"  IP: {login['ip']}")
                print(f"  Hour: {login['hour']}:00")
                print("")
            if len(report['unusual_login_times']) > 5:
                print(f"  ... and {len(report['unusual_login_times']) - 5} more unusual logins")
        else:
            print("- No unusual login times detected")
        
        # IP Analysis
        ip_analysis = report['ip_analysis']
        print("\nIP ADDRESS ANALYSIS:")
        print(f"- Total Unique IPs: {ip_analysis['total_unique_ips']}")
        print(f"- Internal IPs: {ip_analysis['internal_vs_external']['internal']}")
        print(f"- External IPs: {ip_analysis['internal_vs_external']['external']}")
        
        # User Account Changes
        changes = report['user_account_changes']
        print("\nUSER ACCOUNT CHANGES:")
        print(f"- User Creations: {len(changes['user_creations'])}")
        if changes['user_creations']:
            for dt, username in changes['user_creations'][:3]:  # Show first 3 for brevity
                print(f"  - {username} created at {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            if len(changes['user_creations']) > 3:
                print(f"  ... and {len(changes['user_creations']) - 3} more user creations")
        
        print(f"- Password Changes: {len(changes['password_changes'])}")
        if changes['password_changes']:
            for dt, username in changes['password_changes'][:3]:  # Show first 3 for brevity
                print(f"  - {username}'s password changed at {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            if len(changes['password_changes']) > 3:
                print(f"  ... and {len(changes['password_changes']) - 3} more password changes")
        
        print(f"- Permission Changes: {len(changes['permission_changes'])}")
        if changes['permission_changes']:
            for dt, username in changes['permission_changes'][:3]:  # Show first 3 for brevity
                print(f"  - {username}'s permissions changed at {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            if len(changes['permission_changes']) > 3:
                print(f"  ... and {len(changes['permission_changes']) - 3} more permission changes")
        
        # Sudo Command Usage
        print("\nSUDO COMMAND USAGE:")
        sorted_sudo = sorted(report['sudo_command_usage'].items(), key=lambda x: x[1], reverse=True)
        for user, count in sorted_sudo[:5]:  # Show top 5 for brevity
            print(f"- {user}: {count} commands")
        if len(sorted_sudo) > 5:
            print(f"... and {len(sorted_sudo) - 5} more users")
        
        # Unusual Events
        print(f"\nUNUSUAL EVENTS: {report['unusual_events']} events detected")
        
        print("\n" + "="*80)
        print("END OF REPORT")
        print("="*80 + "\n")
    
    def export_report_to_file(self, filename="auth_log_report.txt", report=None):
        """
        Exports the security report to a text file.
        
        Args:
            filename (str): Name of the output file
            report (dict, optional): Report to export. If None, generates a new report.
            
        Returns:
            bool: True if successful, False otherwise
        """
        if report is None:
            report = self.generate_report()
            
        if not report:
            return False
            
        try:
            # Redirect stdout to file temporarily
            original_stdout = sys.stdout
            with open(filename, 'w') as f:
                sys.stdout = f
                self.print_report(report)
            sys.stdout = original_stdout
            
            print(f"Report successfully exported to {filename}")
            return True
        except Exception as e:
            print(f"Error exporting report: {e}")
            sys.stdout = sys.__stdout__  # Ensure stdout is restored
            return False


def main():
    """
    Main function to run the Auth Log Analyzer.
    """
    parser = argparse.ArgumentParser(description='Analyze authentication log files for security insights')
    parser.add_argument('log_file', nargs='?', default='/var/log/auth.log',
                        help='Path to the auth.log file (default: /var/log/auth.log)')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help='Output file for the report (default: print to console)')
    parser.add_argument('-b', '--brute-force-threshold', type=int, default=5,
                        help='Threshold for detecting brute force attacks (default: 5)')
    parser.add_argument('-w', '--time-window', type=int, default=10,
                        help='Time window in minutes for brute force detection (default: 10)')
    
    args = parser.parse_args()
    
    print(f"Auth.log Analysis Tool")
    print(f"Analyzing log file: {args.log_file}")
    
    # Initialize and run the analyzer
    analyzer = AuthLogAnalyzer(args.log_file)
    
    if not analyzer.load_log_file():
        sys.exit(1)
    
    print(f"Successfully loaded log file with {len(analyzer.log_entries)} entries")
    print("Analyzing logs...")
    
    analyzer.analyze_logs()
    
    # Generate and display report
    if args.output:
        analyzer.export_report_to_file(args.output)
    else:
        analyzer.print_report()


if __name__ == "__main__":
    main()
