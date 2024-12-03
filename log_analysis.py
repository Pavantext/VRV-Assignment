import re
import csv
from collections import defaultdict

def parse_log(file_path):
    log_entries = []
    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(r'(?P<ip>\d+\.\d+\.\d+\.\d+) .*"(?P<method>\w+) (?P<endpoint>\/\S*) HTTP\/\d+\.\d+" (?P<status>\d+)', line)
            if match:
                log_entries.append(match.groupdict())
    return log_entries

if __name__ == "__main__":
    log_entries = parse_log('sample.log')
    print(log_entries)