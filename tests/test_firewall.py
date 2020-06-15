import unittest
import encrypted_dns
import dnsmessage


class TestFirewall(unittest.TestCase):
    def setUp(self):
        encrypted_dns.main.start(test=True)

    def test_safe_search(self):
        outbounds = {
            'www.google.com': 'forcesafesearch.google.com',
            'www.bing.com': 'strict.bing.com',
            'www.duckduckgo.com': 'safe.duckduckgo.com',
            'www.youtube.com': 'restrictmoderate.youtube.com',
            'm.youtube.com': 'restrictmoderate.youtube.com',
            'youtubei.googleapis.com': 'restrictmoderate.youtube.com',
            'youtube.googleapis.com': 'restrictmoderate.youtube.com',
            'www.youtube-nocookie.com': 'restrictmoderate.youtube.com'
        }

        for outbound_address, result in outbounds:
            dns_query = dns.message.make_query(outbound_address, dns.rdatatype.A)
            response = dns.query.udp(dns_query, '127.0.0.1', port=53, timeout=60)
            if response.answer:
                resolve_result = response.answer[-1].items[0].to_text()
            self.assertEquals(resolve_result, result)

        def test_refuse_any(self):
            dns_query = dns.message.make_query('localhost', dns.rdatatype.ANY)
            response = dns.query.udp(dns_query, '127.0.0.1', port=53, timeout=3)
            self.assertFalse(response)

        def test_disable_AAAA(self):
            dns_query = dns.message.make_query('localhost', dns.rdatatype.AAAA)
            response = dns.query.tcp(dns_query, '127.0.0.1', port=5301, timeout=3)
            self.assertFalse(response)
        
        def test_rate_limit(self):
            dns_query = dns.message.make_query('localhost', dns.rdatatype.A)
            for _ in range(30):
                dns.query.tcp(dns_query, '127.0.0.1', port=5301, timeout=0.5)
                time.sleep(0.02)
            response = dns.query.tcp(dns_query, '127.0.0.1', port=5301, timeout=0.5)
            self.assertFalse(response)

if __name__ == '__main__':
    unittest.main()
