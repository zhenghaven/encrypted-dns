from encrypted_dns import utils


class ParseQuery:
    def __init__(self, query_data):
        self.data = query_data

    def parse_plain(self):
        query_data = self.data

        header = {
            'transaction_id': query_data[:2],
            'flags': self.parse_flags(query_data[2:4]),
            'question_count': int.from_bytes(query_data[4:6], byteorder='big'),
            'answer_count': int.from_bytes(query_data[6:8], byteorder='big'),
            'name_server_count': int.from_bytes(query_data[8:10], byteorder='big'),
            'additional_record__count': int.from_bytes(query_data[10:12], byteorder='big')
        }

        question = self.parse_question(query_data[12:])
        answer = {}

        parsed_result = [header, question, answer]
        return parsed_result

    @staticmethod
    def parse_flags(flags_data):
        qr = utils.get_bit_from_byte(flags_data[:1], 0)
        qpcode = utils.get_bit_from_byte(flags_data[:1], 1, 4)
        aa = utils.get_bit_from_byte(flags_data[:1], 5)
        tc = utils.get_bit_from_byte(flags_data[:1], 6)
        rd = utils.get_bit_from_byte(flags_data[:1], 7)
        ra = utils.get_bit_from_byte(flags_data[1:2], 0)
        z = utils.get_bit_from_byte(flags_data[1:2], 1, 3)
        rcode = utils.get_bit_from_byte(flags_data[1:2], 4, 7)

        flags = {
            'QR': qr,
            'OPCODE': qpcode,
            'AA': aa,
            'TC': tc,
            'RD': rd,
            'RA': ra,
            'Z': z,
            'RCODE': rcode
        }

        return flags

    @staticmethod
    def parse_question(question_data):
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

        qname = domain_parts
        qtype = question_data[domain_end_point:domain_end_point + 2]
        qclass = question_data[domain_end_point + 2: domain_end_point + 4]

        question = {
            'QNAME': qname,
            'QTYPE': ParseQuery.get_query_type(int.from_bytes(qtype, byteorder='big')),
            'QCLASS': ParseQuery.get_query_class(int.from_bytes(qclass, byteorder='big'))
        }
        return question

    @staticmethod
    def get_query_type(qtype):
        qtype_dict = {
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

        return qtype_dict[qtype]

    @staticmethod
    def get_query_class(qclass):
        qclass_dict = {
            1: 'In',
            2: 'CS',
            3: 'CH',
            4: 'HS'
        }

        return qclass_dict[qclass]


class ParseResponse:
    def __init__(self, response_data):
        pass
