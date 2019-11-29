import encrypted_dns

__VERSION__ = '1.0.0'


def start():
    print("Starting Encrypted-DNS Resolver")
    dns_config_object = encrypted_dns.Config()
    dns_controller = encrypted_dns.server.Controller(dns_config_object)
    dns_controller.start()
