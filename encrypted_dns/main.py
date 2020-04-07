import encrypted_dns
import threading


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
    inbound_list = config.get_config('inbound')

    # check whether to use dns cache
    if config.get_config('enable_cache'):
        cache_object = encrypted_dns.resolve.CacheHandler()
    else:
        cache_object = None

    wire_message_handler_object = encrypted_dns.resolve.WireMessageHandler(
        config.get_config('outbound'),
        cache_object,
        config.get_config('enable_ecs'),
        config.get_config('bootstrap_dns_ip')
    )

    for inbound in inbound_list:
        inbound_object = threading.Thread(
            target=protocol_methods[inbound['protocol']],
            args=(inbound['host'], inbound['port'], wire_message_handler_object),
            daemon=True
        ).start()
        inbound_thread_pool.append(inbound_object)

    while True:
        pass


start()
