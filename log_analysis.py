import re
import csv
from collections import Counter
from prettytable import PrettyTable

# Configuration
LOG_FILE_PATH = "sample.log"
CSV_OUTPUT_PATH = "log_analysis_results.csv"
HTML_OUTPUT_PATH = "log_analysis_report.html"
FAILED_LOGIN_LIMIT = 5

def parse_logs(file_path):
    """
    Extracts log data into a structured format.
    
    Args:
        file_path (str): Path to the log file.
    Returns:
        list[dict]: Structured log data containing IP, method, endpoint, and status.
    """
    with open(file_path, "r") as file:
        logs = file.readlines()

    log_entries = []
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?P<method>\w+) (?P<endpoint>\S+) HTTP/\d+\.\d+" (?P<status>\d+) .*'
    )

    for line in logs:
        match = log_pattern.match(line)
        if match:
            log_entries.append(match.groupdict())

    return log_entries

def count_requests_by_ip(log_entries):
    """
    Counts the number of requests per IP address.

    Args:
        log_entries (list[dict]): Parsed log data.
    Returns:
        list[tuple]: Sorted list of (IP, request_count) tuples.
    """
    ip_counts = Counter(entry['ip'] for entry in log_entries)
    return ip_counts.most_common()

def find_top_endpoint(log_entries):
    """
    Identifies the most frequently accessed endpoint.

    Args:
        log_entries (list[dict]): Parsed log data.
    Returns:
        tuple: Most accessed endpoint and its count, or None if no data.
    """
    endpoint_counts = Counter(entry['endpoint'] for entry in log_entries)
    return endpoint_counts.most_common(1)[0] if endpoint_counts else None

def identify_suspicious_ips(log_entries, threshold=FAILED_LOGIN_LIMIT):
    """
    Detects IPs with failed login attempts exceeding the threshold.

    Args:
        log_entries (list[dict]): Parsed log data.
        threshold (int): Maximum allowed failed login attempts.
    Returns:
        dict: Suspicious IPs with their failed attempt counts.
    """
    failed_attempts = Counter(
        entry['ip'] for entry in log_entries if entry['status'] == '401'
    )
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}

def export_to_csv(ip_data, top_endpoint, suspicious_ips, file_path):
    """
    Saves analysis results to a CSV file.

    Args:
        ip_data (list[tuple]): Requests per IP.
        top_endpoint (tuple): Most accessed endpoint data.
        suspicious_ips (dict): Suspicious activity data.
        file_path (str): CSV file path.
    """
    with open(file_path, "w", newline="") as file:
        writer = csv.writer(file)

        # Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_data)

        # Top Endpoint
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint", "Count"])
        if top_endpoint:
            writer.writerow(top_endpoint)

        # Suspicious IPs
        writer.writerow([])
        writer.writerow(["Suspicious IPs", "Failed Login Attempts"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def export_to_html(ip_data, top_endpoint, suspicious_ips, file_path):
    """
    Generates an HTML report of the analysis.

    Args:
        ip_data (list[tuple]): Requests per IP.
        top_endpoint (tuple): Most accessed endpoint data.
        suspicious_ips (dict): Suspicious activity data.
        file_path (str): HTML file path.
    """
    with open(file_path, "w") as file:
        file.write("""
<html>
<head>
    <title>Log Analysis Report</title>
    <style>
        body { font-family: 'Verdana', sans-serif; margin: 20px; background-color: #eafaf1; color: #2e5d36; }
        h1, h2 { text-align: center; color: #1d4b2c; }
        table { width: 85%; margin: 20px auto; border-collapse: collapse; background-color: #ffffff; }
        th, td { border: 1px solid #d1e7d3; padding: 12px; text-align: center; }
        th { background-color: #3a7947; color: #ffffff; }
        tr:nth-child(even) { background-color: #f4fdf6; }
        tr:nth-child(odd) { background-color: #eafaf1; }
        p { text-align: center; font-size: 1.2em; }
    </style>
</head>
<body>
    <h1>log Analysis Overview</h1>
    <h2>Request Distribution by IP</h2>
    <table>
        <tr><th>IP Address</th><th>Total Requests</th></tr>
""")
        for ip, count in ip_data:
            file.write(f"<tr><td>{ip}</td><td>{count}</td></tr>")
        file.write("""
    </table>
    <h2>Top Endpoint Access</h2>
""")
        if top_endpoint:
            file.write(f"<p><strong>{top_endpoint[0]}</strong> was accessed <strong>{top_endpoint[1]}</strong> times.</p>")
        else:
            file.write("<p>No endpoint data available.</p>")

        file.write("""
    <h2>Suspicious IPs</h2>
    <table>
        <tr><th>IP Address</th><th>Failed login Attempts</th></tr>
""")
        for ip, count in suspicious_ips.items():
            file.write(f"<tr><td>{ip}</td><td>{count}</td></tr>")
        file.write("""
    </table>
</body>
</html>
""")

def display_results(ip_data, top_endpoint, suspicious_ips):
    """
    Prints analysis results to the terminal.

    Args:
        ip_data (list[tuple]): Requests per IP.
        top_endpoint (tuple): Most accessed endpoint data.
        suspicious_ips (dict): Suspicious activity data.
    """
    print("\nRequests Per IP:")
    table = PrettyTable(["IP Address", "Request Count"])
    for ip, count in ip_data:
        table.add_row([ip, count])
    print(table)

    print("\nMost Frequently Accessed Endpoint:")
    if top_endpoint:
        print(f"{top_endpoint[0]} (Accessed {top_endpoint[1]} times)")
    else:
        print("No endpoint data available.")

    print("\nSuspicious IPs:")
    if suspicious_ips:
        table = PrettyTable(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_ips.items():
            table.add_row([ip, count])
        print(table)
    else:
        print("No suspicious activity detected.")

def main():
    """
    Main workflow for log analysis: Parse logs, analyze data, and generate reports.
    """
    log_entries = parse_logs(LOG_FILE_PATH)

    ip_data = count_requests_by_ip(log_entries)
    top_endpoint = find_top_endpoint(log_entries)
    suspicious_ips = identify_suspicious_ips(log_entries)

    display_results(ip_data, top_endpoint, suspicious_ips)
    export_to_csv(ip_data, top_endpoint, suspicious_ips, CSV_OUTPUT_PATH)
    export_to_html(ip_data, top_endpoint, suspicious_ips, HTML_OUTPUT_PATH)

    print(f"\nReports saved to {CSV_OUTPUT_PATH} and {HTML_OUTPUT_PATH}")

if __name__ == "__main__":
    main()
