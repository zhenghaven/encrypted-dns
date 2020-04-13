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

    safe_search = {
        'www.google.com': 'forcesafesearch.google.com',
        'www.bing.com': 'strict.bing.com',
        'www.duckduckgo.com': 'safe.duckduckgo.com',
        'www.youtube.com': 'restrictmoderate.youtube.com',
        'm.youtube.com': 'restrictmoderate.youtube.com',
        'youtubei.googleapis.com': 'restrictmoderate.youtube.com',
        'youtube.googleapis.com': 'restrictmoderate.youtube.com',
        'www.youtube-nocookie.com': 'restrictmoderate.youtube.com'
    }

    inbound_thread_pool = []
    config = encrypted_dns.ConfigHandler().check_format()

    # create cache object
    if config.get_config('dns_cache'):
        cache_object = encrypted_dns.resolve.CacheHandler()
    else:
        cache_object = None

    # parse hosts
    hosts = {}
    hosts_config = config.get_config('rules')
    if hosts_config:
        hosts.update(hosts_config.get('hosts', {}))
        if hosts_config['force_safe_search']:
            hosts.update(safe_search)

    wire_message_handler_object = encrypted_dns.resolve.WireMessageHandler(
        config.get_config('outbounds'),
        cache_object,
        config.get_config('ecs_ip_address'),
        hosts,
        config.get_config('dnssec')
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
