import base64
import socket
import urllib.parse
import urllib.request


class PlainUpstream:
    def __init__(self, upstream_ip, upstream_port=53):
        self.upstream_ip = upstream_ip
        self.upsream_port = upstream_port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _send(self, message_data):
        self.client.sendto(message_data, (self.upstream_ip, self.upsream_port))


class HTTPSUpsream:
    def __init__(self, upstream_url):
        self.upstream_url = upstream_url

    def query(self, query_data):
        base64_query_string = self.struct_query(query_data)
        base64_query_string = base64_query_string.replace('=', '', 2)
        base64_query_string = base64_query_string.replace('+', '', 2)
        print('base64_query_string:', base64_query_string)

        query_parameters = urllib.parse.urlencode({'dns': base64_query_string, 'ct': 'application/dns-message'})
        query_url = self.upstream_url + query_parameters
        query_headers = {}
        query_request = urllib.request.Request(query_url, headers=query_headers)
        print('query_url: ', query_url)

        response_data = urllib.request.urlopen(query_request)
        query_result = response_data.read()
        print('query_result: ', query_result)
        return query_result

    @staticmethod
    def struct_query(query_data):
        base64_query_data = base64.b64encode(query_data)
        base64_query_string = base64_query_data.decode("utf-8")

        return base64_query_string
