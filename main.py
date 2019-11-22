import encrypted_dns

print("Encrypted-DNS Resolver Started")
dns_config_object = encrypted_dns.Config()
dns_controller = encrypted_dns.server.Controller(dns_config_object)
dns_controller.start()
