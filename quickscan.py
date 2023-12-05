#!/usr/bin/env python3

import subprocess
import json
import re
import requests


CREDENTIALS_FILE = 'credentials.json'

def load_credentials():
    with open(CREDENTIALS_FILE, 'r') as file:
        return json.load(file)

def scan_network(network_range):
    try:
        result = subprocess.run(["nmap", "-sn", network_range], capture_output=True, text=True, check=True)
        output = result.stdout
        ip_addresses = re.findall(r'(\d+\.\d+\.\d+\.\d+)', output)
        return ip_addresses
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while scanning the network: {e}")
        return []

def identify_iot_devices(devices):
    iot_devices = []
    for device in devices:
        try:
            result = subprocess.run(["nmap", "-p", "80,443", device], capture_output=True, text=True, check=True)
            output = result.stdout
            if "80/tcp open" in output or "443/tcp open" in output:
                iot_devices.append(device)
        except subprocess.CalledProcessError as e:
            print(f"An error occurred while scanning device {device}: {e}")
    return iot_devices

def check_default_credentials(iot_devices, credentials):
    vulnerable_devices = []
    for device in iot_devices:
        for cred in credentials:
            try:
                url = f"http://{device}/login"
                response = requests.post(url, data={'username': cred['default_username'], 'password': cred['default_password']})
                if response.ok:
                    vulnerable_devices.append({'device': device, 'credentials': cred})
                    break
            except requests.RequestException as e:
                print(f"An error occurred while trying to log into {device}: {e}")
    return vulnerable_devices

def generate_report(vulnerable_devices):
    if not vulnerable_devices:
        print("No vulnerable devices found.")
        return
    print("Vulnerable Devices Found:")
    for device in vulnerable_devices:
        print(f"Device: {device['device']}, Credentials: {device['credentials']['default_username']}/{device['credentials']['default_password']}")

    with open('vulnerability_report.txt', 'w') as file:
        for device in vulnerable_devices:
            file.write(f"Device: {device['device']}, Credentials: {device['credentials']['default_username']}/{device['credentials']['default_password']}\n")

def main():
    network_range = '192.168.0.0/24'
    credentials = load_credentials()
    all_devices = scan_network(network_range)
    iot_devices = identify_iot_devices(all_devices)
    vulnerable_devices = check_default_credentials(iot_devices, credentials)
    generate_report(vulnerable_devices)

if __name__ == "__main__":
    main()
