import logging
import csv
import ipaddress
import pyshark
import nmap
import os
import glob
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PRIVATE_NETWORKS = {ipaddress.ip_network(net) for net in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]}

def is_private_ip(ip):
    return any(ipaddress.ip_address(ip) in network for network in PRIVATE_NETWORKS)

def extract_data_from_pcapng(filename, max_packets=10000):
    unique_ips = set()

    try:
        cap = pyshark.FileCapture(filename, display_filter="ip", keep_packets=True)
        cap.load_packets(packet_count=max_packets)

        for packet in cap:
            src_ip = str(packet.ip.src) 
            dst_ip = str(packet.ip.dst) 
            if src_ip and not is_private_ip(src_ip):
                unique_ips.add(src_ip)
            if dst_ip and not is_private_ip(dst_ip):
                unique_ips.add(dst_ip)

        logging.info(f"Extracted unique IPs from {filename}")
        return unique_ips

    except Exception as e:
        logging.error(f"Error processing {filename}: {e}")
        return set()


def save_ips_to_csv(unique_ips, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Unique IPs"])
        writer.writerows([[ip] for ip in unique_ips])
    logging.info(f"Unique IPs saved to {filename}")

def load_ips_from_csv(filename):
    ips = set()
    try:
        with open(filename, 'r') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)
            for row in reader:
                ips.add(row[0])
    except FileNotFoundError:
        pass
    return ips

def scan_ip(ip):
    nm = nmap.PortScanner()
    result = {}
    try:
        nm.scan(hosts=ip, arguments='-T4 -F')
        for host in nm.all_hosts():
            result[host] = {
                'hostname': nm[host].hostname(),
                'state': nm[host].state(),
                'protocols': nm[host].all_protocols()
            }
    except Exception as e:
        logging.error(f"Error scanning IP {ip}: {e}")
    return result

def main():
    all_unique_ips = set()
    pcap_files = glob.glob('*.pcap')

    for pcap_file in pcap_files:
        unique_ips_for_file = extract_data_from_pcapng(pcap_file)
        all_unique_ips.update(unique_ips_for_file)
        save_ips_to_csv(unique_ips_for_file, f"{os.path.splitext(pcap_file)[0]}_unique_ips.csv")

    all_unique_ips.update(load_ips_from_csv("all_unique_ips.csv"))
    save_ips_to_csv(all_unique_ips, "all_unique_ips.csv")

    with ThreadPoolExecutor(max_workers=10) as executor:
        scan_results = list(executor.map(scan_ip, all_unique_ips))

    for result in scan_results:
        for ip, details in result.items():
            logging.info('----------------------------------------------------')
            logging.info(f"Host: {ip} ({details['hostname']})")
            logging.info(f"State: {details['state']}")
            for proto in details['protocols']:
                logging.info(f"Protocol: {proto}")
                lport = sorted(result[ip][proto].keys())
                for port in lport:
                    logging.info(f'port : {port}\tstate : {result[ip][proto][port]["state"]}')

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"An error occurred: {e}")
