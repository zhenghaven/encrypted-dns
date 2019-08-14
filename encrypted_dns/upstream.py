import base64
import urllib.parse
import urllib.request


class PlainUpstream:
    def __init__(self, client, upstream_ip, upstream_port=53):
        self.upstream_ip = upstream_ip
        self.upsream_port = upstream_port
        self.client = client

    def query(self, query_data):
        self._send(query_data)

    def _send(self, message_data):
        self.client.sendto(message_data, (self.upstream_ip, self.upsream_port))


class HTTPSUpstream:
    def __init__(self, client, upstream_url):
        self.upstream_url = upstream_url
        self.client = client

    def query(self, query_data):
        base64_query_string = self.struct_query(query_data)
        base64_query_string = base64_query_string.replace('=', '')
        base64_query_string = base64_query_string.replace('+', '-')
        base64_query_string = base64_query_string.replace('/', '_')
        print('base64_query_string:', base64_query_string)

        query_parameters = urllib.parse.urlencode({'dns': base64_query_string, 'ct': 'application/dns-message'})
        query_url = self.upstream_url + query_parameters
        query_headers = {}
        query_request = urllib.request.Request(query_url, headers=query_headers)
        print('query_url: ', query_url)

        response_data = urllib.request.urlopen(query_request)
        query_result = response_data.read()
        print('query_result: ', query_result)

        self.client.sendto(query_result, ('127.0.0.1', 53))

    @staticmethod
    def struct_query(query_data):
        base64_query_data = base64.b64encode(query_data)
        base64_query_string = base64_query_data.decode("utf-8")

        return base64_query_string
