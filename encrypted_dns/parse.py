from encrypted_dns import utils


class ParseQuery:
    def __init__(self, query_data):
        self.data = query_data

    def parse_plain(self):
        query_data = self.data

        header = {
            'transaction_id': query_data[:2],
            'flags': self._parse_flags(query_data[2:4]),
            'question_count': query_data[4:6],
            'answer_count': query_data[6:8],
            'name_server_count': query_data[8:10],
            'additional_record__count': query_data[10:12]
        }

        question = self._parse_question(query_data[12:])
        answer = {}

        parsed_result = [header, question, answer]
        return parsed_result

    @staticmethod
    def _parse_flags(flags_data):
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
    def _parse_question(question_data):
        state = False
        expected_length = 0
        domain_string = ''
        domain_parts = []
        domain_end_point = 0
        pointer = 0

        for byte in question_data:
            print(chr(byte))
            print(pointer)
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
        qtype = question_data[domain_end_point + 1:domain_end_point + 3]

        question = {
            'QNAME': qname,
            'QTYPE': qtype
        }
        return question


class ParseResponse:
    def __init__(self, response_data):
        pass
