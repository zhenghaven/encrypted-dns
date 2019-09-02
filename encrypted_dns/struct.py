import os

from encrypted_dns import utils


class StructQuery:
    def __init__(self, address, query_type='A'):
        self.address = address
        self.query_type = query_type
        self.transaction_id = os.urandom(2)

    def struct(self):
        query_data = bytes()
        header = self.struct_header()
        question = self.struct_question(self.address, self.query_type)
        query_data += header
        query_data += question
        return query_data, self.transaction_id

    def struct_header(self, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0,
                      rcode=0, qcount=1, ancount=0, nscount=0, arcount=0):
        header = bytes(self.transaction_id)
        bit_cache = list()
        bit_cache.append(qr)
        bit_cache = bit_cache + utils.get_bit_list_from_integer(opcode, 4)
        bit_cache.append(aa)
        bit_cache.append(tc)
        bit_cache.append(rd)
        header += utils.get_bytes_from_bits(bit_cache)

        bit_cache = list()
        bit_cache.append(ra)
        bit_cache = bit_cache + utils.get_bit_list_from_integer(z, 3)
        bit_cache = bit_cache + utils.get_bit_list_from_integer(rcode, 4)
        header += utils.get_bytes_from_bits(bit_cache)

        header += bytes([qcount, ancount, nscount, arcount])

        return header

    @staticmethod
    def struct_question(qname_string, qtype, qclass='IN'):
        question = bytearray()
        qname_string = qname_string.split('.')

        for split_name in qname_string:
            question.append(len(split_name))
            question.extend(bytearray(split_name, 'utf-8'))

        question.append(0x00)

        qtype = utils.get_record_type(qtype)
        question.append(qtype)

        qclass = utils.get_record_class(qclass)
        question.append(qclass)
        return question


class StructResponse:
    def __init__(self):
        pass
