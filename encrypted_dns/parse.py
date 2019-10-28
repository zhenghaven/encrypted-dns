from encrypted_dns import utils


class ParseHeader:

    @staticmethod
    def parse_header(data):
        header = {
            'transaction_id': data[:2].hex(),
            'flags': ParseHeader.parse_flags(data[2:4]),
            'question_count': int.from_bytes(data[4:6], byteorder='big'),
            'answer_count': int.from_bytes(data[6:8], byteorder='big'),
            'name_server_count': int.from_bytes(data[8:10], byteorder='big'),
            'additional_record__count': int.from_bytes(data[10:12], byteorder='big')
        }

        return header

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


class ParseQuestion:
    @staticmethod
    def parse_question(question_data):
        domain_parts, domain_end_point = utils.get_domain_name_from_question_data(question_data)
        qname = domain_parts
        qtype = question_data[domain_end_point:domain_end_point + 2]
        qclass = question_data[domain_end_point + 2:domain_end_point + 4]

        question = {
            'QNAME': qname,
            'QTYPE': utils.get_record_type(int.from_bytes(qtype, byteorder='big')),
            'QCLASS': utils.get_record_class(int.from_bytes(qclass, byteorder='big'))
        }
        return question, domain_end_point + 4


class ParseAnswer:
    @staticmethod
    def parse_answer(data, end_point, answer_count):
        answer_list = list()
        end_point += 12

        for answer in range(answer_count):
            compression_offset = int.from_bytes(data[end_point:end_point + 2], byteorder='big') - 49152
            domain_parts, cache_end_point = utils.get_domain_name_from_question_data(data[compression_offset:])

            record_type = utils.get_record_type(int.from_bytes(data[end_point + 2:end_point + 4], byteorder='big'))
            record_class = utils.get_record_class(int.from_bytes(data[end_point + 4:end_point + 6], byteorder='big'))
            ttl = int.from_bytes(data[end_point + 6:end_point + 10], byteorder='big')
            length = int.from_bytes(data[end_point + 10:end_point + 12], byteorder='big')
            record = data[end_point + 12:end_point + 12 + length]

            end_point = end_point + 12 + length

            if record_type == 'A':
                address = ''
                for i in range(len(record)):
                    address_split = int.from_bytes(record[i:i + 1], byteorder='big')
                    address = address + str(address_split) + '.'
                record = address.rstrip('.')

            elif record_type == 'CNAME':
                pass

            answer_list.append(
                {'domain_name': domain_parts,
                 'type': record_type,
                 'class': record_class,
                 'ttl': ttl,
                 'length': length,
                 'record': record
                 }
            )
        return answer_list


class ParseQuery:
    def __init__(self, query_data):
        self.data = query_data

    def parse_plain(self):
        query_data = self.data

        header = ParseHeader.parse_header(query_data[:12])
        question, question_end_point = ParseQuestion.parse_question(query_data[12:])

        parsed_result = [header, question]
        return parsed_result


class ParseResponse:
    def __init__(self, response_data):
        self.data = response_data

    def parse_plain(self):
        response_data = self.data
        header = ParseHeader.parse_header(response_data[:12])
        question, question_end_point = ParseQuestion.parse_question(response_data[12:])
        answer_count = header['answer_count']
        answer = ParseAnswer.parse_answer(response_data, question_end_point, answer_count)
        parsed_result = [header, question, answer]
        return parsed_result
