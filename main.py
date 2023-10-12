import logging
import csv
import ipaddress
import pyshark
import nmap
import argparse
import json
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import psutil
import geoip2.database

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_PRIVATE_NETWORKS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

def is_private_ip(ip, private_networks):
    for network in private_networks:
        if ipaddress.ip_address(ip) in network:
            return True
    return False

def get_most_used_interface():
    interface_stats = psutil.net_io_counters(pernic=True)
    return max(interface_stats, key=lambda k: interface_stats[k].packets_sent + interface_stats[k].packets_recv)

def get_geolocation(ip, db_path):
    try:
        reader = geoip2.database.Reader(db_path)
        response = reader.city(ip)
        country_code = response.country.iso_code
        city_name = response.city.name
        org = response.traits.organization
        reader.close()
        return {"country": country_code, "city": city_name, "organization": org}
    except Exception as e:
        logger.error(f"Error performing geolocation for IP {ip}: {e}")
        return None

def save_ips_to_csv(unique_ips, filename, db_path):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Unique IPs", "Country", "City", "Organization"])
        for ip in unique_ips:
            geolocation = get_geolocation(ip, db_path)
            if geolocation:  # Check if geolocation is not None
                writer.writerow([ip, geolocation["country"], geolocation["city"], geolocation["organization"]])
            else:
                writer.writerow([ip, "Unknown", "Unknown", "Unknown"])
        logger.info(f"Unique IPs with geolocation saved to {filename}")

def extract_data_from_interface(packet_filter='ip', max_packets=10000, private_networks=[]):
    interface = get_most_used_interface()
    captured_packets = pyshark.LiveCapture(interface=interface, display_filter=packet_filter)
    unique_ips = set()
    packet_counter = 0

    for packet in captured_packets.sniff_continuously():
        if packet_counter >= max_packets:
            break
        try:
            if hasattr(packet, 'ip'):
                source_ip = packet.ip.src
                destination_ip = packet.ip.dst
                if not is_private_ip(source_ip, private_networks):
                    unique_ips.add(source_ip)
                if not is_private_ip(destination_ip, private_networks):
                    unique_ips.add(destination_ip)
        except AttributeError:
            continue
        packet_counter += 1
    return unique_ips


def scan_ip(ip, scan_arguments='-T4 -A -O -sV'):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments=scan_arguments)
        return {
            ip: {
                'hostname': nm[ip].hostname(),
                'state': nm[ip].state(),
                'protocols': nm[ip].all_protocols(),
                'info': nm[ip]['hostnames']
            }
        }
    except Exception as e:
        logger.error(f"Error scanning IP {ip}: {e}")
        return None

def save_results_to_json(data, filename):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, indent=4)
        logger.info(f"Scan results saved to {filename}")

def main(args):
    private_networks = [ipaddress.ip_network(net) for net in args.private_networks]
    all_unique_ips = extract_data_from_interface(packet_filter=args.packet_filter, max_packets=args.max_packets, private_networks=private_networks)
    save_ips_to_csv(all_unique_ips, args.output_file, args.geoip_db)

    aggregated_results = defaultdict(dict)
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        scan_results = executor.map(scan_ip, all_unique_ips)
        for result in scan_results:
            if result:
                aggregated_results.update(result)

    save_results_to_json(aggregated_results, args.results_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Advanced Network Monitoring Tool')
    parser.add_argument('--max-packets', type=int, default=10000, help='Maximum packets to sniff')
    parser.add_argument('--workers', type=int, default=10, help='Number of worker threads')
    parser.add_argument('--output-file', type=str, default='all_unique_ips.csv', help='Output CSV file for unique IPs')
    parser.add_argument('--private-networks', nargs='*', default=DEFAULT_PRIVATE_NETWORKS, help='List of private networks')
    parser.add_argument('--packet-filter', type=str, default='ip', help='Custom packet filter (e.g., "tcp or udp")')
    parser.add_argument('--results-file', type=str, default='scan_results.json', help='Output JSON file for scan results')
    parser.add_argument('--geoip-db', type=str, default='path_to_geoip2_database.mmdb', help='Path to the GeoLite2 database file')
    parser.add_argument('--timing', type=str, default='T4', help='Nmap scan timing template (e.g., "T4", "T1")')
    
    args = parser.parse_args()

    try:
        main(args)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
