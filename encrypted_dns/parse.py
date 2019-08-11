class ParseQuery:
    def __init__(self, query_data):
        self.data = query_data

    def parse_plain(self):
        query_data = self.data

        header = {
            'transaction_id': query_data[:2],
            'flags': self._parse_flags(query_data[:2])
        }

        question = {}
        answer = {}

        parsed_result = {header, question, answer}
        return parsed_result

    @staticmethod
    def _parse_flags(flags_data):
        flags = {
            'QR': flags_data[:1],
            '': ''
        }

        return flags


class ParseResponse:
    def __init__(self, response_data):
        pass
