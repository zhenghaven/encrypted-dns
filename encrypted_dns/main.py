import threading

import encrypted_dns


def _udp_inbound(host, port, core_object):
    return encrypted_dns.inbound.DatagramInbound.serve(host, port, core_object)


def _tcp_inbound(host, port, core_object):
    pass


def start():
    protocol_methods = {
        'udp': _udp_inbound,
        'tcp': _tcp_inbound
    }
    inbound_thread_pool = []
    config = encrypted_dns.ConfigHandler().check_format()

    if config.get_config('dns_cache'):
        cache_object = encrypted_dns.resolve.CacheHandler()
    else:
        cache_object = None

    wire_message_handler_object = encrypted_dns.resolve.WireMessageHandler(
        config.get_config('outbounds'),
        cache_object,
        config.get_config('ecs_ip_address')
    )

    for inbound in config.get_config('inbounds'):
        protocol, host, port = encrypted_dns.utils.parse_dns_address(inbound)
        inbound_object = threading.Thread(
            target=protocol_methods[protocol],
            args=(host, port, wire_message_handler_object),
            daemon=True
        ).start()
        inbound_thread_pool.append(inbound_object)

    while True:
        pass


start()
