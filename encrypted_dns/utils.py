def get_bit_from_byte(byte, begin, end=None):
    if end is None:
        end = begin

    result = ''
    for bit in range(begin, end + 1):
        result += str(ord(byte) & (1 << bit))
    return result
