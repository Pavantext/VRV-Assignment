# Log Analysis Script

This Python project analyzes server log files to extract and analyze key information. The script performs essential log processing tasks like counting requests per IP, identifying frequently accessed endpoints, and detecting suspicious activities.

## Dependencies
- `Python 3.7 or higher`
  
## Libraries:
- `pandas (for version 2)`
- `re`
- `csv`
- 
## Features

1. **Count Requests per IP Address**  
   - Parses the log file to count the number of requests made by each IP address.  
   - Displays the results in descending order of request counts.

2. **Identify Most Frequently Accessed Endpoint**  
   - Extracts endpoints (e.g., URLs or resource paths) and identifies the one accessed the most.  

3. **Detect Suspicious Activity**  
   - Flags IP addresses with more than a configurable number of failed login attempts (default threshold: 10).  

4. **Output Results**  
   - Displays results in the terminal and saves them to a CSV file named `log_analysis_results.csv`  (v1.0), (v1.1) respectfully.

## Project Versions  

- **Version 1**: Implements the core functionality using `collections.Counter` and basic file handling.  
- **Version 2**: Optimized using the `pandas` library for more efficient data handling and analysis.

---

## Installation

1. Clone the repository:  
   ```bash
   git clone https://github.com/Pavantext/VRV-Assignment.git
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/MacOS
   venv\Scripts\activate     # Windows
3. Install the required dependencies for version (1.1):
```bash
   pip install -r requirements(V1.1).txt
```

# Usage
### Add your log file (e.g., sample.log) to the project directory.
### Run the script For version(1.0):
```bash
python log_analysis(1.0).py
```
### Run the script for version(1.1):
```bash
python log_analysis(1.1).py
```
### View the results:
### Terminal output will display the analysis.
Results will also be saved to log_analysis_results.csv, (v1.0), (v1.1) respectively.



