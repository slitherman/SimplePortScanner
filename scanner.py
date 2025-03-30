import sys
import socket
from datetime import datetime
import json
import ipaddress
from cli import CLI


#TODO: Use the rich library to spice up the UI https://github.com/Textualize/rich?tab=readme-ov-file

def tcp_scan(target_ip,start_port, end_port, timeout = 2, with_dns_lookup = False):
    ports = []
    hostname = reverse_dns_lookup(target_ip)
    print(f"Running tcp scan on {target_ip} (ports) {start_port} - {end_port} ")
    if hostname:
        print(f"Hostname from DNS lookup: {hostname}")   
    for port in range(start_port,end_port + 1):
       with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        connection = sock.connect_ex((target_ip, port))
        if connection == 0:
            ports.append(port)
    ports_str = ", ".join(map(str, ports))
    print(f"Target {hostname or target_ip} scanned. These ports are currently open {ports_str}")
    return ports

def udp_scan(target_ip, start_port, end_port, timeout = 2, with_dns_lookup = False):
    ports = []
    hostname = reverse_dns_lookup(target_ip)
    print(f"Running udp scan on {target_ip} (ports) {start_port} - {end_port} ")
    if hostname:
          print(f"Hostname from DNS lookup: {hostname}")  

    for port in range(start_port,end_port +1 ):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            connection = sock.connect_ex((target_ip, port))
            if connection == 0:
                ports.append(port)
    ports_str = ", ".join(map(str, ports))
    print(f"Target {hostname or target_ip} scanned. These ports are currently open {ports_str}")
    return ports

def scan_range(cidr_notation, start_port, end_port, timeout = 2, scan_type ="both"):
    network = ipaddress.ip_network(cidr_notation)  
    for ip in network.hosts():
        ip_str = str(ip)
        print(f"Scanning {ip_str}")
        if scan_type == "tcp":
            tcp_scan(ip_str, start_port, end_port, timeout)
        elif scan_type == "udp":
          udp_scan(ip_str, start_port, end_port, timeout )
        elif scan_type == "both":  
            tcp_scan(ip_str, start_port, end_port, timeout)
            udp_scan(ip_str, start_port, end_port, timeout )
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
    """
    Perform a reverse DNS lookup on the given IP address,
    returning the primary hostname if one is found.
    """
    try:
        host_tuple = socket.gethostbyaddr(ip_address)
        domain = host_tuple[0]
        return domain
    except socket.error as e:
        print("Could not map IP address to hostname. Make sure the IP address is valid.")
        
     
def dns_lookup_all_ips(hostname):
    """
    Uses getaddrinfo() to fetch all IPv4/IPv6 addresses for the hostname.
    Returns a set of (family, ip_address) pairs.
    """
    address = set()
    try:
        results = socket.getaddrinfo(hostname, None)
        for res in results:
            family, socktype, proto, canonname, sockaddr = res 
            # sockaddr could be (ip, port) for IPv4 or (ip, port, flowinfo, scopeid) for IPv6
            ip = sockaddr[0]
            address.add((family,ip))
        return address
    except socket.error as e:
         print("Could not map hostname to IP address. Make sure the hostname is valid.")
         

def scan_all_addresses_of_hostname(hostname, start_port, end_port, timeout = 2, scan_type="both"):
    """
    Resolve all IP addresses (IPv4 and IPv6) associated with a given hostname,
    and perform port scanning on each resolved address.
    
    Behavior:
    ---------
    - Uses `dns_lookup_all_ips()` to resolve all IPs associated with the hostname.
    - Iterates over each resolved IP address and performs the selected scan type.
    - Prints the results of each scan for each resolved IP.

    Returns:
    --------
    None
    """
    all_addresses = dns_lookup_all_ips(hostname)
    if not all_addresses:
      print(f"No addresses found for {hostname}.")
      return
    for family,ip in all_addresses:
        print(f"scanning {ip} (family={family})")
        if scan_type == "tcp":
            open_tcp_ports = tcp_scan(ip,start_port,end_port,timeout)
            print(f"Open TCP ports on {ip}: {open_tcp_ports}")
        elif scan_type =="udp":
            open_udp_ports = udp_scan(ip,start_port,end_port,timeout)
            print(f"Open UDP ports on {ip}: {open_udp_ports}")
        elif scan_type == "both":
            open_tcp_ports = tcp_scan(ip, start_port, end_port, timeout)
            open_udp_ports = udp_scan(ip, start_port, end_port, timeout)
            print(f"Open TCP ports on {ip}: {open_tcp_ports}")
            print(f"Open UDP ports on {ip}: {open_udp_ports}")
        else:
            print(f"Unknown scan type: {scan_type}")  
        
def json_logger():
    pass

def service_version():
    pass

def main():

    cli = CLI()
    print("This is a very simple port scanner.")
    print("It currently only supports TCP scanning, UDP scanning and banner grabbing.")
    print("Example usage: python3 scanner.py scan 192.168.50.229 --scan-type tcp  -sp 1 -ep 10000 -time 2")
    print("Enter -h or --help to access the help menu.")
    args = cli.parser.parse_args()
    if args.command == "scan":
        scan_type = args.scan_type
        target = args.target_ip
        start_port = args.start_port
        end_port = args.end_port
        timeout = args.timeout
        with_dns_lookup = args.dns_lookup
        if scan_type == "tcp":
            tcp_scan(target,start_port,end_port,timeout, with_dns_lookup)
        if scan_type == "udp":
            udp_scan(target,start_port,end_port,timeout, with_dns_lookup)
        
        if with_dns_lookup == True:
            scan_all_addresses_of_hostname(target,start_port,end_port,timeout, scan_type)
            
    elif args.command == "banner":
          target = args.target_ip
          port = args.port
          timeout = args.timeout
          data = args.data
          banner_grab(target,port,timeout, data)
    elif args.command == "version":
        print("Port Scanner version 1.0")
    
  
  
main()
    
