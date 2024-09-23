# The Ultimate Nmap Scanner (AKA The Network Ninja)

Warning: this script may cause excessive awesomeness, spontaneous high-fiving, and a strong urge to scan all the things.

## Table of Contents

- Requirements (a.k.a. The Usual Suspects)
- Usage (a.k.a. The Mission Briefing)
- Features
- Note (a.k.a. The Fine Print)

## Requirements (a.k.a. The Usual Suspects)

- Python 3.x
- nmap library (pip install python-nmap)

## Usage (a.k.a. The Mission Briefing)

1. Clone the repository or download the script.
2. Install the required libraries using `pip install -r requirements.txt`. I promise it won't take longer than a coffee break.
3. Run the script using `python nmap_scanner.py`.
4. Follow the prompts to choose the scan type and enter the IP address or list of IP addresses. Don't worry, we won't judge you if you scan your own network.

## Features

- Network Scan
  Performs a ping scan to discover hosts in the network. Like a digital game of hide-and-seek.
- Port Scan
  Performs a TCP scan to identify open ports on the host. Because who doesn't love a good game of "find the open port"?
- Full Scan
  Performs a TCP scan on all ports (65535) to identify open ports on the host. For the truly paranoid.
- UDP Scan
  Performs a UDP scan to identify open UDP ports on the host. Because UDP is like the cool kid on the block.
- Vulns Scan
  Checks for known vulnerabilities on the host using Nmap scripts. A.K.A. the "please don't let me get pwned" scan.
- Recon Scan
  Provides a list of useful reconnaissance commands. For the aspiring network ninja.
- All Scan
  Performs all the above scans. Because why choose just one?
- Scan List
  Scans a list of IP addresses.

## Note (a.k.a. The Fine Print)

- The UDP scan requires root privileges and will prompt for confirmation before proceeding.
- The script uses the nmap library to perform scans. Ensure that the library is installed and the script has the necessary permissions to run nmap scans.

## Also Note
  
- This README.md file was modified by A.I, because why not!

