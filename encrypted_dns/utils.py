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
