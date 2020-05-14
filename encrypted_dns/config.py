import json
import os


class ConfigHandler:
    def __init__(self):
        self.DEFAULT_CONFIG = {
            'log': False,
            'ecs_ip_address': '1.2.3.4',
            'dnssec': False,

            'dns_cache': {
                'enable': True,
                'override_ttl': 3600
            },

            'firewall': {
                'refuse_ANY': True,
                'AAAA_disabled': False,
                'rate_limit': 30,
                'client_blacklist': [
                    '1.2.3.4'
                ]
            },

            'rules': {
                'force_safe_search': False,
                'hosts': {
                    'localhost': '127.0.0.1',
                    'cloudflare-dns.com': '1.0.0.1',
                    'dns.google': '8.8.4.4'
                }
            },

            'inbounds': [
                '0.0.0.0:53',
                'tcp://0.0.0.0:5301'
            ],

            'outbounds': [
                {
                    'tag': 'bootstrap',
                    'dns': ['1.0.0.1'],
                    'domains': [
                        "captive.apple.com",
                        "connectivitycheck.gstatic.com",
                        "detectportal.firefox.com",
                        "msftconnecttest.com",
                        "nmcheck.gnome.org",
                        "pool.ntp.org",
                        "time.apple.com",
                        "time.asia.apple.com",
                        "time.euro.apple.com",
                        "time.nist.gov",
                        "time.windows.com"
                    ]
                },
                {
                    'tag': 'unencrypted',
                    'dns': ['1.0.0.1', 'tcp://8.8.4.4'],
                    'concurrent': False,
                    'domains': ['sub:youtube.com', 'include:netflix.com']
                },
                {
                    'tag': 'encrypted',
                    'dns': ['https://cloudflare-dns.com', 'tls://dns.google'],
                    'concurrent': False,
                    'domains': ['all']
                }
            ]
        }

        self.config = {}
        self.home = os.path.expanduser("~")
        self.file_name = self.home.rstrip('/') + '/.config/encrypted_dns/config.json'
        self.load()

    def check_format(self):
        return self

    def get_config(self, key=None):
        if key is None:
            return self.config
        elif key in self.config:
            return self.config[key]

    def edit_config(self, key, value):
        if key in self.config:
            self.config[key] = value

    def get_default_config(self):
        return self.DEFAULT_CONFIG

    def load(self):
        file_init = os.path.isfile(self.file_name)
        if not file_init:
            self.config = self.get_default_config()
            self.save()
            print('Generated default config file:', self.file_name)
            print('Please edit config file and restart Encrypted-DNS Resolver')
            exit()
        else:
            config_file = open(self.file_name)
            self.config = json.loads(config_file.read())
            print('Load config file:', self.file_name)

    def save(self):
        if not os.path.exists(self.home.rstrip('/') + '/.config/'):
            os.makedirs(self.home.rstrip('/') + '/.config/')

        if not os.path.exists(self.home.rstrip('/') + '/.config/encrypted_dns'):
            os.makedirs(self.home.rstrip('/') + '/.config/encrypted_dns')

        config_json = json.dumps(self.config, indent=4)
        config_file = open(self.file_name, "w")
        config_file.write(config_json)
