import re
import pandas as pd

def parse_log(file_path):
    log_entries = []
    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(
                r'(?P<ip>\d+\.\d+\.\d+\.\d+) .*"(?P<method>\w+) (?P<endpoint>/\S*) HTTP/\d+\.\d+" (?P<status>\d+)', 
                line
            )
            if match:
                log_entries.append(match.groupdict())
    return pd.DataFrame(log_entries)

def analyze_logs(df, threshold=10):
    ip_requests = df['ip'].value_counts().reset_index()
    ip_requests.columns = ['IP Address', 'Request Count']
    
    endpoint_counts = df['endpoint'].value_counts()
    if not endpoint_counts.empty:
        most_accessed = endpoint_counts.reset_index()
        most_accessed.columns = ['Endpoint', 'Access Count']
        most_accessed_endpoint = most_accessed.iloc[0].to_dict()
    else:
        most_accessed_endpoint = {'Endpoint': None, 'Access Count': 0}
    

    failed_attempts = df[df['status'] == '401']['ip'].value_counts()
    if not failed_attempts.empty:
        suspicious_ips = failed_attempts[failed_attempts > threshold].reset_index()
        suspicious_ips.columns = ['IP Address', 'Failed Login Count']
    else:
        suspicious_ips = pd.DataFrame(columns=['IP Address', 'Failed Login Count'])
    
    return ip_requests, most_accessed_endpoint, suspicious_ips


def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, file_name='log_analysis_results(v1.1).csv'):
    
    with open(file_name, 'w') as file:
        file.write("Requests per IP Address\n")
        ip_requests.to_csv(file, index=False)
        
        file.write("\nMost Frequently Accessed Endpoint\n")
        file.write(f"Endpoint,Access Count\n{most_accessed_endpoint['Endpoint']},{most_accessed_endpoint['Access Count']}\n")
        
        file.write("\nSuspicious Activity Detected\n")
        if not suspicious_ips.empty:
            suspicious_ips.to_csv(file, index=False)
        else:
            file.write("Threshold set to default 10 logs. So, no suspicious activity detected more than 10 with same ip address.\n")

if __name__ == "__main__":
    log_file = 'sample.log'
    df = parse_log(log_file)
    
    ip_requests, most_accessed_endpoint, suspicious_ips = analyze_logs(df)

    print("Requests per IP Address:")
    print(ip_requests)
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint['Endpoint']} (Accessed {most_accessed_endpoint['Access Count']} times)")
    
    if suspicious_ips.empty:
        print("\nThreshold set to default 10 logs. So, no suspicious activity detected more than 10 with same ip address.")
    else:
        print("\nSuspicious Activity Detected:")
        print(suspicious_ips)
    
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips)
    print("\nResults saved to 'log_analysis_results(v1.1).csv'")
