import unittest
import time
import encrypted_dns
import dnsmessage


class TestRedirect(unittest.TestCase):
    def setUp(self):
        encrypted_dns.main.start(test=True)
    
    def test_void(self):
        dns_query = dns.message.make_query('testvoid.com', dns.rdatatype.A)
        response = dns.query.udp(dns_query, '127.0.0.1', port=53, timeout=3)
        self.assertFalse(response)

    def test_void_subdomain(self):
         queries = {
            "testsub.com",
            "www.testsub.com",
            "www.dns.testsub.com"
        }
        for query_address in queries:
            dns_query = dns.message.make_query(dns_query, dns.rdatatype.A)
            response = dns.query.udp(dns_query, '127.0.0.1', port=53, timeout=3)
            self.assertFalse(response)

    def test_void_include(self):
        queries = {
            "testinclude",
            "testinclude.com",
            "www.testinclude.com"
        }
        for query_address in queries:
            dns_query = dns.message.make_query(dns_query, dns.rdatatype.A)
            response = dns.query.udp(dns_query, '127.0.0.1', port=53, timeout=3)
            self.assertFalse(response)


if __name__ == '__main__':
    unittest.main()
