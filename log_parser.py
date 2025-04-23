import re
from collections import defaultdict

def analyze_log(file_path):
    suspicious_ips = defaultdict(int)
    suspicious_users = set(['admin', 'root', 'test'])
    flagged_entries = []

    with open(file_path, 'r') as log:
        for line in log:
            if "Failed password" in line:
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                user_match = re.search(r'for (\w+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    suspicious_ips[ip] += 1
                if user_match:
                    user = user_match.group(1)
                    if user in suspicious_users:
                        flagged_entries.append(line.strip())

    print("Suspicious IPs with failed attempts:")
    for ip, count in suspicious_ips.items():
        if count >= 3:
            print(f"- {ip} ({count} failures)")

    print("\nFlagged login attempts using blacklisted usernames:")
    for entry in flagged_entries:
        print(f"- {entry}")

if __name__ == "__main__":
    analyze_log("test_logs/auth_sample.log")