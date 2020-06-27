import time
import unittest

import dns.exception
import dns.message
import dns.query


class TestRedirect(unittest.TestCase):
    def test_void(self):
        dns_query = dns.message.make_query('testvoid.com', dns.rdatatype.A)
        response = dns.query.udp(dns_query, '127.0.0.1', port=53, timeout=3)
        self.assertFalse(response)

    def test_void_subdomain(self):
        queries = [
            "1.testsub.com",
            "www.testsub.com",
            "www.dns.testsub.com"
        ]
        for query_address in queries:
            dns_query = dns.message.make_query(query_address, dns.rdatatype.A)
            with self.assertRaises(dns.exception.Timeout):
                response = dns.query.udp(dns_query, '127.0.0.1', port=53, timeout=3)
                print(response)
            time.sleep(0.1)

    def test_void_include(self):
        queries = {
            "testinclude",
            "testinclude.com",
            "www.testinclude.com"
        }
        for query_address in queries:
            dns_query = dns.message.make_query(query_address, dns.rdatatype.A)
            with self.assertRaises(dns.exception.Timeout):
                response = dns.query.udp(dns_query, '127.0.0.1', port=53, timeout=2)
                print(response)
            time.sleep(0.1)


if __name__ == '__main__':
    unittest.main()
