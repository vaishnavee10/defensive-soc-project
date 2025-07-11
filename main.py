import re
from collections import defaultdict
import matplotlib.pyplot as plt
import pandas as pd
import os
from datetime import datetime

# Step 1: Parse SSH log file
ssh_log_path = 'logs/ssh.log'
failed_attempts = defaultdict(int)

with open(ssh_log_path, 'r') as file:
    lines = file.readlines()

print("\nDetected Failed SSH Login Attempts:\n")
for line in lines:
    if "Failed password" in line:
        match = re.search(r'Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)', line)
        if match:
            username = match.group(1)
            ip = match.group(2)
            failed_attempts[ip] += 1
            print(f"Failed login attempt by user '{username}' from IP: {ip}")

# Step 2: Detect Brute-Force IPs
print("\nBrute-Force Attack Suspects (More than 5 failed attempts):\n")
ips = []
counts = []

for ip, count in failed_attempts.items():
    if count > 5:
        print(f"Suspicious IP: {ip} — {count} failed attempts")
        ips.append(ip)
        counts.append(count)

# Step 3: Visualize Brute-Force IPs with Bar Chart (Improved)
if ips:
    plt.figure(figsize=(8, 4))
    bars = plt.bar(ips, counts, width=0.5, color="#100706", edgecolor='black')

    # Add value labels
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, yval + 0.3, int(yval), ha='center', va='bottom', fontsize=9)

    plt.xlabel('IP Address', fontsize=11, weight='bold')
    plt.ylabel('Failed Attempts', fontsize=11, weight='bold')
    plt.title('Brute-Force Attackers (SSH)', fontsize=13, weight='bold')
    plt.xticks(rotation=30, ha='right', fontsize=9)
    plt.yticks(fontsize=9)
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.show()
else:
    print("\nNo brute-force IPs with more than 5 attempts found.")

# Step 4: Export SSH brute-force alerts to CSV
alert_data = {
    "IP Address": ips,
    "Failed Attempts": counts
}

if alert_data["IP Address"]:
    df = pd.DataFrame(alert_data)
    os.makedirs("output", exist_ok=True)
    csv_path = "output/ssh_alerts.csv"
    df.to_csv(csv_path, index=False)
    print(f"\nSSH alert report saved to: {csv_path}")
else:
    print("\nNo SSH brute-force alerts to export.")

# Step 5: Analyze Apache log for scanning patterns
apache_log_path = 'logs/apache.log'
ip_to_urls = defaultdict(set)

if os.path.exists(apache_log_path):
    with open(apache_log_path, 'r') as file:
        for line in file:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?"GET (.*?) HTTP', line)
            if match:
                ip = match.group(1)
                url = match.group(2)
                ip_to_urls[ip].add(url)

    # Print scanning suspects
    print("\nScanning Suspects (More than 10 unique pages accessed):\n")
    for ip, urls in ip_to_urls.items():
        if len(urls) > 10:
            print(f"Suspicious IP: {ip} — accessed {len(urls)} unique pages")
else:
    print(f"\nApache log file not found at: {apache_log_path}")

# Step 6: Export Apache scanning suspects to CSV
scan_alerts = {
    "IP Address": [],
    "Unique Pages Accessed": []
}

for ip, urls in ip_to_urls.items():
    if len(urls) > 10:
        scan_alerts["IP Address"].append(ip)
        scan_alerts["Unique Pages Accessed"].append(len(urls))

if scan_alerts["IP Address"]:
    df_scan = pd.DataFrame(scan_alerts)
    os.makedirs("output", exist_ok=True)
    scan_csv_path = "output/apache_scan_alerts.csv"
    df_scan.to_csv(scan_csv_path, index=False)
    print(f"\n Apache scan alert report saved to: {scan_csv_path}")
else:
    print("\n No scanning activity found to export.")


# Step 7: Detect DoS attempts from Apache log
print("\nDoS Suspects (More than 100 requests in a minute):\n")

dos_attempts = defaultdict(lambda: defaultdict(int))  # {IP: {minute: count}}

if os.path.exists(apache_log_path):
    with open(apache_log_path, 'r') as file:
        for line in file:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2})', line)
            if match:
                ip = match.group(1)
                raw_time = match.group(2)
                try:
                    timestamp = datetime.strptime(raw_time, "%d/%b/%Y:%H:%M")
                    minute_key = timestamp.strftime("%Y-%m-%d %H:%M")
                    dos_attempts[ip][minute_key] += 1
                except ValueError:
                    pass  # ignore lines with malformed timestamps

    # Print DoS suspects
    for ip, minute_counts in dos_attempts.items():
        for minute, count in minute_counts.items():
            if count > 100:
                print(f"Suspicious IP: {ip} — {count} requests at {minute}")
else:
    print("Apache log file not found for DoS detection.")

# Step 8: Check against Blacklist
print("\nChecking if suspicious IPs are in blacklist...")

blacklist_path = 'blacklist/blacklist.txt'

try:
    with open(blacklist_path, "r") as f:
        blacklisted_ips = set(line.strip() for line in f if line.strip())

    # Use previously detected brute-force IPs
    matched = set(ips).intersection(blacklisted_ips)

    if matched:
        print("\nMatched Blacklisted IPs:")
        for ip in matched:
            print(ip)
    else:
        print("No blacklisted IPs matched.")

except FileNotFoundError:
    print("Error: blacklist.txt not found.")
