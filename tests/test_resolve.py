import time
import unittest

import dns.message
import dns.query

import encrypted_dns


class TestResolve(unittest.TestCase):
    def test_resolve_outbound_ip(self):
        hosts_dict = {
            'dns.google': '8.8.4.4',
            'cloudflare-dns.com': '1.0.0.1'
        }
        queries = {
            'berkeley.edu': '35.163.72.93',
            'ucla.edu': '128.97.27.37',
            'dns.google': '8.8.4.4',
            'cloudflare-dns.com': '1.0.0.1'
        }
        dns_address = '1.0.0.1'
        for query_address, result in queries.items():
            resolve_result = encrypted_dns.resolve.core.OutboundHandler.resolve_outbound_ip(
                query_address,
                dns_address,
                hosts_dict
            )
            self.assertEqual(result, resolve_result)

    def test_udp_server(self):
        dns_query = dns.message.make_query('localhost', dns.rdatatype.A)
        response = dns.query.udp(dns_query, '127.0.0.1', port=53, timeout=5)
        if response.answer:
            result = response.answer[-1].items[0].to_text()
            self.assertEqual(result, '127.0.0.1')

    def test_tcp_server(self):
        dns_query = dns.message.make_query('localhost', dns.rdatatype.A)
        response = dns.query.tcp(dns_query, '127.0.0.1', port=5301, timeout=5)
        if response.answer:
            result = response.answer[-1].items[0].to_text()
            self.assertEqual(result, '127.0.0.1')

    def test_cache(self):
        dns_query = dns.message.make_query('www.netflix.com', dns.rdatatype.A)
        response = dns.query.udp(dns_query, '127.0.0.1', port=53, timeout=5)
        if response.answer:
            response.answer[-1].items[0].to_text()

        start_time = time.time()
        cached_response = dns.query.udp(dns_query, '127.0.0.1', port=53, timeout=5)
        if cached_response.answer:
            cached_response.answer[-1].items[0].to_text()
        end_time = time.time()
        self.assertTrue(end_time - start_time < 0.1)


if __name__ == '__main__':
    unittest.main()
