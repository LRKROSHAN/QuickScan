#!/usr/bin/env python3

import subprocess
import json
import re
import requests

# Path to your JSON or CSV file containing default credentials
CREDENTIALS_FILE = 'credentials.json'

def load_credentials():
    """
    Load default credentials from a JSON file.
    """
    with open(CREDENTIALS_FILE, 'r') as file:
        return json.load(file)

def scan_network(network_range):
    """
    Scan the network using nmap and return the list of devices.
    """
    try:
        # Running nmap scan
        result = subprocess.run(["nmap", "-sn", network_range], capture_output=True, text=True, check=True)
        output = result.stdout

        # Regular expression to extract IP addresses
        ip_addresses = re.findall(r'(\d+\.\d+\.\d+\.\d+)', output)
        return ip_addresses
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while scanning the network: {e}")
        return []

def identify_iot_devices(devices):
    """
    Identify IoT devices from the list of devices.
    This could be based on open ports, device names, etc.
    """
    iot_devices = []
    for device in devices:
        try:
            # Running nmap to check for specific open ports
            result = subprocess.run(["nmap", "-p", "80,443", device], capture_output=True, text=True, check=True)
            output = result.stdout

            # Check if standard web ports are open; this is a naive check
            if "80/tcp open" in output or "443/tcp open" in output:
                iot_devices.append(device)
        except subprocess.CalledProcessError as e:
            print(f"An error occurred while scanning device {device}: {e}")

    return iot_devices


def check_default_credentials(iot_devices, credentials):
    """
    Attempt to log into IoT devices using the default credentials.
    """
    vulnerable_devices = []
    for device in iot_devices:
        for cred in credentials:
            try:
                # Assuming the IoT device has a web interface at port 80
                url = f"http://{device}/login"  # Adjust the URL based on the device's login page
                response = requests.post(url, data={'username': cred['default_username'], 'password': cred['default_password']})

                if response.ok:
                    # Assuming a successful login redirects to a dashboard or similar
                    vulnerable_devices.append({'device': device, 'credentials': cred})
                    break  # Exit the inner loop if credentials are found
            except requests.RequestException as e:
                print(f"An error occurred while trying to log into {device}: {e}")
                continue  # Continue with the next credentials

    return vulnerable_devices


def generate_report(vulnerable_devices):
    """
    Generate a report of devices with default credentials.
    """
    if not vulnerable_devices:
        print("No vulnerable devices found.")
        return

    print("Vulnerable Devices Found:")
    for device in vulnerable_devices:
        print(f"Device: {device['device']}, Credentials: {device['credentials']['default_username']}/{device['credentials']['default_password']}")

    # Optionally, write this report to a file
    with open('vulnerability_report.txt', 'w') as file:
        for device in vulnerable_devices:
            file.write(f"Device: {device['device']}, Credentials: {device['credentials']['default_username']}/{device['credentials']['default_password']}\n")


def main():
    credentials = load_credentials()
    all_devices = scan_network()
    iot_devices = identify_iot_devices(all_devices)
    vulnerable_devices = check_default_credentials(iot_devices, credentials)
    generate_report(vulnerable_devices)

if __name__ == "__main__":
    main()
