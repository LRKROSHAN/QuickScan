import nmap
import json
import requests

# Function to attempt login with given credentials
def attempt_login(url, username, password):
    try:
        response = requests.post(url, data={'username': username, 'password': password})
        if response.status_code == 200 and "Logged in successfully" in response.text:
            return True
        return False
    except requests.RequestException:
        return False

# Load default credentials
with open('credentials.json') as f:
    default_credentials = json.load(f)

# Initialize Nmap Scanner
nm = nmap.PortScanner()

# Scan the local network for open ports 5000 and 5001
nm.scan(hosts='10.0.2.0/24', arguments='-p 5000,5001')

# Open a file to write the vulnerability report
with open('vulnerability_report.txt', 'w') as report_file:
    vulnerabilities_found = False
    for host in nm.all_hosts():
        for port in ['5000', '5001']:
            if nm[host].has_tcp(int(port)) and nm[host]['tcp'][int(port)]['state'] == 'open':
                url = f'http://{host}:{port}'
                for cred in default_credentials:
                    if attempt_login(url, cred['default_username'], cred['default_password']):
                        report = f"Vulnerabilities Found. Device: {host}, Credentials: {cred['default_username']}/{cred['default_password']}\n"
                        report_file.write(report)
                        print(report.strip())  # Print to terminal
                        vulnerabilities_found = True
                        break

    if not vulnerabilities_found:
        report_file.write("No vulnerabilities found.\n")
        print("No vulnerabilities found.")  # Print to terminal

    report_file.write("\n")

if __name__ == '__main__':
    print("QuickScan Complete")
    with open('vulnerability_report.txt', 'a') as report_file:
        report_file.write("End Of Report\n")
