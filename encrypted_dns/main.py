import threading
import time
import sys
import argparse
import logging

import encrypted_dns


def create_inbound(protocol, host, port, core_object):
    if protocol == 'udp':
        return encrypted_dns.inbound.DatagramInbound.serve(host, port, core_object)
    elif protocol == 'tcp':
        return encrypted_dns.inbound.StreamInbound.serve(host, port, core_object)
    elif protocol in {'https', 'doh', 'tls', 'dot'}:
        raise ValueError("{} inbound protocol is not supported yet".format(protocol))
    else:
        raise ValueError("Unknown inbound protocol '{}'".format(protocol))


def start(test=False):
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config',     required=False, type=str,  help="Path to configuration file.",  default="default_config.json")
	parser.add_argument('-l', '--log',        required=False, type=str,  help="Path to log file.")
	parser.add_argument('-d', '--debug',      required=False,            help="Enable logging debug message.", action='store_true')
    args = parser.parse_args()

	if args.log is None:
		logging.basicConfig(format='[%(asctime)s][%(name)s](%(levelname)s) %(message)s',
							level='DEBUG' if args.debug else 'INFO',
							stream=sys.stdout)
	else:
		logging.basicConfig(format='[%(asctime)s][%(name)s](%(levelname)s) %(message)s',
							level='DEBUG' if args.debug else 'INFO',
							filename=args.log)

    logger = logging.getLogger("encrypted_dns")

    safe_search = {
        'include:google.': 'forcesafesearch.google.com',
        'www.bing.com': 'strict.bing.com',
        'www.duckduckgo.com': 'safe.duckduckgo.com',
        'www.youtube.com': 'restrictmoderate.youtube.com',
        'm.youtube.com': 'restrictmoderate.youtube.com',
        'youtubei.googleapis.com': 'restrictmoderate.youtube.com',
        'youtube.googleapis.com': 'restrictmoderate.youtube.com',
        'www.youtube-nocookie.com': 'restrictmoderate.youtube.com'
    }

    inbound_thread_pool = []
    try:
        if test:
            config = encrypted_dns.ConfigHandler(args.config).set_default_config()
        else:
            config = encrypted_dns.ConfigHandler(args.config).check_format()

        # create cache object
        if config.get_config('dns_cache')['enable']:
            cache_object = encrypted_dns.resolve.CacheHandler(
                config.get_config('dns_cache')['override_ttl']
                )
        else:
            cache_object = None

        # parse hosts
        hosts = dict()
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
            config.get_config('dnssec'),
            config.get_config('firewall')
        )

        for inbound in config.get_config('inbounds'):
            protocol, host, port = encrypted_dns.utils.parse_dns_address(inbound)
            inbound_object = threading.Thread(
                target=create_inbound,
                args=(protocol, host, port, wire_message_handler_object),
                daemon=True
            ).start()
            inbound_thread_pool.append(inbound_object)

        while True:
            time.sleep(1)

    except Exception as exc:
        logger.exception(exc)
    except KeyboardInterrupt:
        pass
    finally:
        for t in inbound_thread_pool:
            if t and t.is_alive():
                t.stop()


if __name__ == "__main__":
    start()
