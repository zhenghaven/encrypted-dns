import socket
import logging


def parse_domain_rules(rules, name, default=None):
    result = default
    priority = 0
    for i in rules.keys():
        # from lowest priority to highest
        if i == 'all' and priority < 1:
            result = rules[i]
            priority = 0
        elif i.startswith('include:') and i[9:] in name and priority < 2:
            result = rules[i]
            priority = 1
        elif i.startswith('sub:') and name.endswith(i[5:]) and priority < 3:
            result = rules[i]
            priority = 2
        elif name == i:
            result = rules[i]
    return result


def parse_dns_address(dns_address):
    logger = logging.getLogger("encrypted_dns.utils")
    try:
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
            dns_address = dns_address[0].rstrip('/')
        return protocol, dns_address, port
    except Exception as exc:
        logger.exception(exc)


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
