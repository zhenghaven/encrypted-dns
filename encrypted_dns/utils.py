import socket


def parse_dns_address(dns_address):
    port_dict = {
        'doh': 443,
        'https': 443,
        'tls': 853,
        'dot': 853,
        'tcp': 53,
        'udp': 53
    }

    if '://' not in dns_address:
        protocol = 'udp'
    else:
        dns_address = dns_address.split('://')
        protocol = dns_address[0]
        dns_address = dns_address[1]

    if ':' not in dns_address:
        port = port_dict[protocol]
    else:
        dns_address = dns_address.split(':')
        port = int(dns_address[1])
        dns_address = dns_address[0]

    return protocol, dns_address, port


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False
    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:
        return False
    return True
