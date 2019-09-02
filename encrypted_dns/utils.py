import socket


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
        for i in range(length - len(bit_list) - 1):
            bit_list.insert(0, 0)
    return bit_list


def get_bytes_from_bits(bits):
    bits = iter(bits)
    done = False
    while not done:
        byte = 0
        for _ in range(0, 8):
            try:
                bit = next(bits)
            except StopIteration:
                bit = 0
                done = True
            byte = (byte << 1) | bit
        yield byte


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

    result = None
    if isinstance(record_type, int):
        result = record_type_dict[record_type]
    elif isinstance(record_type, str):
        reverse_dict = dict((v, k) for k, v in record_type_dict.items())
        result = reverse_dict[record_type]

    return result


def get_record_class(record_class):
    record_class_dict = {
        1: 'IN',
        2: 'CS',
        3: 'CH',
        4: 'HS',
        255: '*'
    }

    result = None
    if isinstance(record_class, int):
        result = record_class_dict[record_class]
    elif isinstance(record_class, str):
        reverse_dict = dict((v, k) for k, v in record_class_dict.items())
        result = reverse_dict[record_class]

    return result
