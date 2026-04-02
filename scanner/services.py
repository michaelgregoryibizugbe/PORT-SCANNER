"""
Known port-to-service mappings and top port lists.
"""

# Common port -> service mapping
PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 43: "WHOIS", 53: "DNS", 67: "DHCP-Server",
    68: "DHCP-Client", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPCBind", 119: "NNTP", 123: "NTP",
    135: "MS-RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 464: "Kerberos-Change", 465: "SMTPS",
    514: "Syslog", 515: "LPD", 520: "RIP", 521: "RIPng",
    587: "SMTP-Submission", 636: "LDAPS", 873: "Rsync",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1434: "MSSQL-Browser", 1521: "Oracle-DB",
    1723: "PPTP", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel-SSL", 2181: "ZooKeeper", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 4443: "HTTPS-Alt",
    5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes-API",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9090: "Prometheus", 9200: "Elasticsearch", 9418: "Git",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB",
    50000: "SAP", 50070: "HDFS",
}

# Top 100 most common ports (based on nmap frequency data)
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106,
    110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427,
    443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
    631, 636, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028,
    1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900,
    6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155,
    49156, 49157,
]

# Top 1000 (abbreviated — add the full nmap list for production)
TOP_1000_PORTS = sorted(set(
    TOP_100_PORTS + list(range(1, 1025)) + [
        1080, 1194, 1241, 1311, 1434, 1521, 1524, 1812, 1813,
        2082, 2083, 2181, 2222, 2375, 2376, 3000, 3128, 3268,
        3269, 3333, 3690, 4000, 4443, 4444, 4567, 4711, 4712,
        4993, 5000, 5001, 5003, 5004, 5060, 5061, 5432, 5555,
        5672, 5683, 5900, 5901, 5984, 5985, 5986, 6000, 6379,
        6443, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667,
        6668, 6669, 7000, 7001, 7002, 7199, 7443, 8000, 8008,
        8080, 8081, 8088, 8443, 8880, 8888, 9000, 9042, 9043,
        9060, 9080, 9090, 9091, 9200, 9300, 9418, 9443, 9999,
        10000, 10250, 10443, 11211, 11300, 15672, 27017, 27018,
        28017, 50000, 50070,
    ]
))


def get_service_name(port: int) -> str:
    """Return known service name for a port, or 'unknown'."""
    return PORT_SERVICES.get(port, "unknown")


def get_top_ports(n: int) -> list[int]:
    """Return the top N ports."""
    if n <= 100:
        return TOP_100_PORTS[:n]
    return TOP_1000_PORTS[:n]
