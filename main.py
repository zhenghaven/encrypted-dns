import encrypted_dns

print("Encrypted-DNS Resolver Started")
dns_config_object = encrypted_dns.Config()
plain_dns_server = encrypted_dns.server.PlainServer(dns_config_object)
plain_dns_server.start()
