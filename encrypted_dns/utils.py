import socket


def parse_dns_address(dns_address):
    if '://' not in dns_address:
        protocol = 'udp'
    else:
        dns_address = dns_address.split('://')
        protocol = dns_address[0]
        dns_address = dns_address[1]

    if ':' not in dns_address:
        port = 53
    else:
        dns_address = dns_address.split(':')
        port = dns_address[1]
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
