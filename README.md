# PCAP Network Analyzer and Scanner

## Overview
This script offers an automated approach to extract unique IP addresses from `.pcap` files found in the current directory. After extraction, the IPs are saved into individual `.csv` files, and an Nmap scan is conducted on them.

## Prerequisites

### Software Requirements:
- **Python** (3.x recommended)
- **Nmap**: Ensure `nmap` is installed and available in your system's PATH.
- **WireShark**

### Python Libraries:
The following Python libraries are required:
- pyshark
- python-nmap
- ipaddress
- logging
- csv
- glob
- os

Install the required Python libraries with the following command:
```bash
pip install pyshark python-nmap
```

## Usage

1. Place all your `.pcap` files in the script's directory.
2. Run the script:
```bash
python main.py
```
3. The script will generate individual `.csv` files for each `.pcap` file containing unique IP addresses, and also an aggregated file named `all_unique_ips.csv`.
4. After extraction, an Nmap scan will be performed on the IPs, and the results will be displayed.
