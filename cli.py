import argparse
class CLI:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="A simple port scanner :D")
        self.subparser = self.parser.add_subparsers(dest="command", help="Select a command: 'scan' to perform a port scan or 'version' to display version info")
        # Subcommand: scan
        scan_parser = self.subparser.add_parser("scan", help="Scan ports on a target.")
        # Positional arg for the target
        scan_parser.add_argument("target_ip",  help ="Target hostname or IP/cidr")
        # Optional args for port range, timeout and software version
        scan_parser.add_argument("--scan-type", choices=["tcp", "udp", "both"], required=True, default="tcp",
                                 help="Type of scan to be performed. Choices: tcp, udp, both (default: tcp)" )
        scan_parser.add_argument("-sp", "--start-port", type=int, default=1, help="Start port (default: 1)")
        scan_parser.add_argument("-ep", "--end-port", type=int, default=1024, help="End port (default: 1024)")
        scan_parser.add_argument("-time", "--timeout", type=int, default=2, help="connection timeout in seconds (default 2 seconds)")
        #TODO Nmap like version detection is not easy to implement. Save this
        #scan_parser.add_argument("-v", "--v", help="Find software vesion. Usually used in conjunction with a port scan.")
        # Subcommand: version
        version_parser = self.subparser.add_parser("version", help="Show version information.")
        
        # Sucommand: Banner grabbing
        banner_parser = self.subparser.add_parser("banner", help="Grab information about a computer and the services running on an open port.")
        
        banner_parser.add_argument("target_ip", help=" hostname or IP")
        banner_parser.add_argument("-p", "--port", type=int, default=80, help="Open port used for banner grabbing (default: 80 )")
        banner_parser.add_argument("-time", "--timeout", type=int, default=2, help="connection timeout in seconds (default: 2 seconds)")
        banner_parser.add_argument("-d", "--data", default="GET / HTTP/1.0\r\n\r\n", help="Data to be sent to the given service (default: get request)")