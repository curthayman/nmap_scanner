# Nmap Scanner

This is a Python script that uses the `nmap` library to scan networks and hosts for open ports, vulnerabilities, and perform reconnaissance.

## Requirements

- Python 3.x
- `nmap` library (`pip install python-nmap`)

## Usage

1. Clone the repository or download the script.
2. Install the required libraries using `pip install -r requirements.txt`.
3. Run the script using `python nmap_scanner.py`.
4. Follow the prompts to choose the scan type and enter the IP address or list of IP addresses.

## Features

- Network Scan: Performs a ping scan to discover hosts in the network.
- Port Scan: Performs a TCP scan to identify open ports on the host.
- Full Scan: Performs a TCP scan on all ports (65535) to identify open ports on the host.
- UDP Scan: Performs a UDP scan to identify open UDP ports on the host.
- Vulns Scan: Checks for known vulnerabilities on the host using Nmap scripts.
- Recon Scan: Provides a list of useful reconnaissance commands.
- All Scan: Performs all the above scans.
- Scan List: Scans a list of IP addresses.

## Note

- The UDP scan requires root privileges and will prompt for confirmation before proceeding.
- The script uses the `nmap` library to perform scans. Ensure that the library is installed and the script has the necessary permissions to run `nmap` scans.
