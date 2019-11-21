import socket
import ipaddress
from encrypted_dns import parse, struct


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


def get_bit_list_from_integer(n, length):
    bit_list = [1 if digit == '1' else 0 for digit in bin(n)[2:]]
    if len(bit_list) < length:
        for i in range(length - len(bit_list)):
            bit_list.insert(0, 0)
    return bit_list


def get_bytes_from_bits(bits):
    index = 7
    integer = 0
    for i in bits:
        integer += i * (2 ** index)
        index -= 1

    return integer.to_bytes(1, byteorder='big')


def get_bit_from_byte(byte, begin, end=None):
    integer = int.from_bytes(byte, byteorder='big')
    bin_list = [int(x) for x in bin(integer)[2:]]
    for i in range(8 - len(bin_list)):
        bin_list.insert(0, 0)

    if end is None:
        end = begin

    result_list = bin_list[begin:end + 1]
    result = ''.join(str(x) for x in result_list)

    return result


def get_domain_name_from_question_data(question_data):
    state = False
    expected_length = 0
    domain_string = ''
    domain_parts = []
    domain_end_point = 0
    pointer = 0

    for byte in question_data:
        if state:
            pointer += 1
            domain_string += chr(byte)

            if pointer == expected_length:
                domain_parts.append(domain_string)
                domain_string = ''
                state = False
                pointer = 0

            if byte == 0:
                domain_parts.append(domain_string)
                break
        else:
            state = True
            expected_length = byte

        domain_end_point += 1

    return domain_parts, domain_end_point


def get_record_type(record_type):
    record_type_dict = {
        1: 'A',
        2: 'NS',
        3: 'MD',
        4: 'MF',
        5: 'CNAME',
        6: 'SOA',
        7: 'MB',
        8: 'MG',
        9: 'MR',
        10: 'NULL',
        11: 'WKS',
        12: 'PTR',
        13: 'HINFO',
        14: 'MINFO',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
        33: 'SRV',
        35: 'NAPTR',
        48: 'DNSKEY',
        250: 'TSIG',
        252: 'AXFR',
        253: 'MAILB',
        254: 'MAILA',
        255: '*',
        256: 'URI'
    }

    if isinstance(record_type, int) and record_type in record_type_dict:
        return record_type_dict[record_type]
    elif isinstance(record_type, str):
        reverse_dict = dict((v, k) for k, v in record_type_dict.items())
        if record_type in reverse_dict:
            return reverse_dict[record_type]
    else:
        return ''


def is_china_address(net_list, ip_address):
    try:
        for net in net_list:
            if ipaddress.ip_address(ip_address) in ipaddress.ip_network(net):
                return True
        return False
    except Exception as exc:
        print(exc)


def get_domain_name_string(query_name_list):
    if len(query_name_list) != 0 and query_name_list[-1] == '\x00':
        query_name_list.pop(-1)
        query_name = '.'.join(query_name_list)
    else:
        query_name = ''
    return query_name


def get_record_class(record_class):
    record_class_dict = {
        1: 'IN',
        2: 'CS',
        3: 'CH',
        4: 'HS'
    }

    if isinstance(record_class, int) and record_class in record_class_dict:
        return record_class_dict[record_class]
    elif isinstance(record_class, str):
        reverse_dict = dict((v, k) for k, v in record_class_dict.items())
        if record_class in reverse_dict:
            return reverse_dict[record_class]
    else:
        return ''


def get_ip_address(client_object, address, bootstrap_dns_object):
    if address == 'dns.google' or address == 'dns.google.com':
        return '8.8.4.4'
    elif address == '1.1.1.1' or address == '1.0.0.1' or 'cloudflare-dns.com' in address:
        return '1.0.0.1'
    elif address == 'dns.quad9.net':
        return '9.9.9.9'

    query_struct = struct.StructQuery(address)
    query_data, transaction_id = query_struct.struct()
    client_object.dns_map[transaction_id] = address

    bootstrap_dns_object.query(query_data)
    while True:
        recv_data, recv_address = client_object.server.recvfrom(512)
        recv_header = parse.ParseHeader.parse_header(recv_data)
        if recv_header['flags']['QR'] == '1' and recv_header['transaction_id'] in client_object.dns_map \
                and client_object.dns_map[recv_header['transaction_id']] == address:
            response = client_object.handle_response(recv_data)
            address = response[2][0]['record']
            return address

