import os

from encrypted_dns import utils


def struct_question(qname_string, qtype, qclass='IN'):
    question = bytearray()
    qname_string = qname_string.split('.')
    for split_name in qname_string:
        question.append(len(split_name))
        question.extend(bytearray(split_name, 'utf-8'))

    question.append(0x00)

    qtype = utils.get_record_type(qtype)
    question += qtype.to_bytes(2, byteorder='big')

    qclass = utils.get_record_class(qclass)
    question += qclass.to_bytes(2, byteorder='big')
    return question


def struct_header(transaction_id, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0,
                  rcode=0, qcount=1, ancount=0, nscount=0, arcount=0):
    header = bytes(transaction_id)
    bit_cache = list()
    bit_cache.append(qr)
    bit_cache = bit_cache + utils.get_bit_list_from_integer(opcode, 4)
    bit_cache.append(aa)
    bit_cache.append(tc)
    bit_cache.append(rd)
    header += utils.get_bytes_from_bits(bit_cache)

    bit_cache = list()
    bit_cache.append(ra)
    bit_cache += utils.get_bit_list_from_integer(z, 3)
    bit_cache += utils.get_bit_list_from_integer(rcode, 4)

    header += utils.get_bytes_from_bits(bit_cache)
    header += qcount.to_bytes(2, byteorder='big')
    header += ancount.to_bytes(2, byteorder='big')
    header += nscount.to_bytes(2, byteorder='big')
    header += arcount.to_bytes(2, byteorder='big')

    return header


class StructQuery:
    def __init__(self, address, query_type='A'):
        self.address = address
        self.query_type = query_type
        self.transaction_id = os.urandom(2)

    def struct(self):
        query_data = bytes()
        header = struct_header(self.transaction_id, qr=0, ancount=0)
        question = struct_question(self.address, self.query_type)
        query_data += header
        query_data += question
        return query_data, self.transaction_id.hex()


class StructResponse:
    def __init__(self, address, transaction_id, record, record_type='A', question_type='A'):
        self.address = address
        self.record = record
        self.question_type = question_type
        self.record_type = record_type
        self.transaction_id = bytes.fromhex(transaction_id)

    def struct(self):
        response_data = bytes()

        header = struct_header(self.transaction_id, qr=1, ancount=1)
        question = struct_question(self.address, self.question_type)

        compression_offset = len(header) + 49152
        compression_offset = compression_offset.to_bytes(2, byteorder='big')
        answer = self.struct_answer(self.record, question_type=self.question_type, record_type=self.record_type, offset=compression_offset)
        response_data += header
        response_data += question
        response_data += answer
        return response_data

    @staticmethod
    def struct_answer(record, record_type='A', question_type='A', record_class='IN', ttl=300, offset=None, address=None):
        answer_data = bytes()
        record_data = bytes()

        if offset is not None:
            answer_data += offset
        elif address is not None:
            address_list = address.split('.')
            for part in address_list:
                answer_data += len(part).to_bytes(1, byteorder='big')
                answer_data += part.encode('utf-8')
            answer_data += b'\x00'
        else:
            return None

        answer_data += utils.get_record_type(record_type).to_bytes(2, byteorder='big')
        answer_data += utils.get_record_class(record_class).to_bytes(2, byteorder='big')
        answer_data += ttl.to_bytes(4, byteorder='big')

        if record_type == 'A':
            record = record.split('.')
            for part in record:
                record_data += int(part).to_bytes(1, byteorder='big')

        if record_type == 'CNAME':
            record_list = record.split('.')
            for part in record_list:
                record_data += len(part).to_bytes(1, byteorder='big')
                record_data += part.encode('utf-8')
            record_data += b'\x00'
            
        record_length = len(record_data)
        answer_data += record_length.to_bytes(2, byteorder='big')
        answer_data += record_data

        return answer_data
