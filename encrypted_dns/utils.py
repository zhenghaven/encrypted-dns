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

    # result = ''
    # for bit in range(begin, end + 1):
    #     result += str(ord(byte) & (1 << bit))
    return result
