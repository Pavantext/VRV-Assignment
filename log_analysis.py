import re
import csv
from collections import defaultdict, Counter

def parse_log(file_path):
    log_entries = []
    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(r'(?P<ip>\d+\.\d+\.\d+\.\d+) .*"(?P<method>\w+) (?P<endpoint>\/\S*) HTTP\/\d+\.\d+" (?P<status>\d+)', line)
            if match:
                log_entries.append(match.groupdict())
    return log_entries

def count_request_by_ip(log_entries):
    ip_counts = Counter(entry['ip'] for entry in log_entries)
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_ip_counts


def find_most_accessed_endpoint(log_entries):
    endpoint_counts = Counter(entry['endpoint'] for entry in log_entries)
    most_accessed = endpoint_counts.most_common(1)
    return most_accessed[0] if most_accessed else None

def detect_suspicious_activity(log_entries, threshold=10):
    failed_attempts = defaultdict(int)
    for entry in log_entries:
        if entry['status'] == '401':
            failed_attempts[entry['ip']] += 1
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return suspicious_ips

def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, file_name='log_analysis_results.csv'):
    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)


        writer.writerow(['ip Address', 'Request Count'])
        writer.writerows(ip_requests)


        writer.writerow([])
        writer.writerow(['Most Frequently Accessed Endpoints'])
        if most_accessed_endpoint:
            writer.writerow(['Endpoint', 'Access Count'])
            writer.writerow(most_accessed_endpoint)

        writer.writerow([])
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['Ip Address', 'Failed Login Count'])
        if suspicious_ips:    
            writer.writerows(suspicious_ips.items())


if __name__ == "__main__":
    log_file = 'sample.log'
    log_entries = parse_log(log_file)


    ip_requests = count_request_by_ip(log_entries)
    print("Request per IP Addess:")
    for ip, count in ip_requests:
        print(f"{ip}: {count}")

    most_accessed_endpoint = find_most_accessed_endpoint(log_entries)
    if most_accessed_endpoint:
        print("\nMost Frequently Accesed Endpoint:")
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    else:
        print("\nNo endpoints found.")



    suspicious_ips = detect_suspicious_activity(log_entries)
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip}: {count} failed login attempts")


    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips)
    print("\nResults saved to 'log_analysis_results.csv'")