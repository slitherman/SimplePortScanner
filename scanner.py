import sys
import socket
from datetime import datetime
import json
import ipaddress
from cli import CLI


#TODO: Use the rich library to spice up the UI https://github.com/Textualize/rich?tab=readme-ov-file

def tcp_scan(target_ip, start_port, end_port, timeout = 2):
    ports = []
    print(f"Running tcp scan on {target_ip} (ports) {start_port} - {end_port} ")
    for port in range(start_port,end_port + 1):
       with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        connection = sock.connect_ex((target_ip, port))
        reverse_dns_lookup(target_ip)
        if connection == 0:
            ports.append(port)
    ports_str = ", ".join(map(str, ports))
    print(f"Target {target_ip} scanned. These ports are currenntly open {ports_str}")
    return ports

def udp_sscan(target_ip, start_port, end_port, timeout = 2):
    ports = []
    print(f"Running udp scan on {target_ip} (ports) {start_port} - {end_port} ")
    for port in range(start_port,end_port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            connection = sock.connect_ex((target_ip, port))
            reverse_dns_lookup(target_ip)
            if connection == 0:
                ports.append(port)
    ports_str = ", ".join(map(str, ports))
    print(f"Target {target_ip} scanned. These ports are currenntly open {ports_str}")
    return ports

def scan_range(cidr_notation, start_port, end_port, timeout = 2, scan_type ="both"):
    network = ipaddress.ip_network(cidr_notation)  
    for ip in network.hosts():
        ip_str = str(ip)
        print(f"Scanning {ip_str}")
        if scan_type == "tcp":
            tcp_scan(ip_str, start_port, end_port, timeout)
        elif scan_type == "udp":
          udp_sscan(ip_str, start_port, end_port, timeout )
        elif scan_type == "both":  
            tcp_scan(ip_str, start_port, end_port, timeout)
            udp_sscan(ip_str, start_port, end_port, timeout )
        else:
            print(f"Unknown scan type: {scan_type}")
def banner_grab(ip_address, port, timeout = 2, send_data = None):
    """
    Attempt to grab a banner from the given IP/port.
    
    :param ip_address:   The target IP address or hostname.
    :param port:         The port to connect to.
    :param timeout:      Connection timeout in seconds.
    :param send_data:    Optional data to send after connecting.
                         Useful for prompting a banner in services
                         that don't send one automatically.
    :return:             The banner (string) if successful, or None if not.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip_address,port))
             # If we need to prompt the server for a banner, send minimal data
            # Example: for HTTP, send a GET request; for SMTP, you might do EHLO
            if send_data:
                sock.sendall(send_data.encode("ascii"))
            response = sock.recv(1024)
            banner = response.decode(errors="ignore")
            print(f"Service grabbed: {banner}")
            return banner.strip()
    except (socket.timeout, ConnectionRefusedError):
        return None
    except Exception as e:
       print(f"Error grabbing banner from {ip_address}:{port} - {e}")
       return None   
def reverse_dns_lookup(ip_address):
    try:
        host = socket.gethostbyaddr(ip_address)
        domain = host[0]
        return domain
    except socket.error as e:
        print("Could not map IP address to hostname. Make sure the IP address is valid.")
    
def json_logger():
    pass

def service_version():
    pass

def main():
 # We expect up to 4 arguments (beyond the script name):
    # 1) target_or_cidr  - Could be "192.168.1.10" or "192.168.1.0/24"
    # 2) start_port      - default 1
    # 3) end_port        - default 1024
    # 4) timeout         - default 2 seconds
    #
    # Example usage:
    #   python scanner.py  scan -t 192.168.1.10 -sp 20 -ep 100 - time 2
    #   python scanner.py 192.168.1.0/24 20 100 2
    cli = CLI()
 # Parse command-line arguments
    print("This is a very simple port scanner.")
    print("It currently only supports TCP scanning, UDP scanning and banner grabbing.")
    print("Example usage: python3 scanner.py scan 192.168.50.229 --scan-type tcp  -sp 1 -ep 10000 -time 2")
    print("Enter -h or --help to access the help menu.")
    args = cli.parser.parse_args()
    if args.command == "scan":
        target = args.target_ip
        start_port = args.start_port
        end_port = args.end_port
        timeout = args.timeout
        tcp_scan(target,start_port,end_port,timeout)
    if args.command == "banner":
          target = args.target_ip
          port = args.port
          timeout = args.timeout
          data = args.data
          banner_grab(target,port,timeout, data)
    elif args.command == "version":
        print("Port Scanner version 1.0")
  
  
main()
    
