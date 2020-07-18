import json
import os
import logging


class ConfigHandler:
    def __init__(self, configPathStr):
        self.DEFAULT_CONFIG = {
            "version": "1.2.0",
            "ecs_ip_address": "128.97.0.0",
            "dnssec": False,

            "dns_cache": {
                "enable": True,
                "override_ttl": 3600
            },

            "firewall": {
                "refuse_ANY": True,
                "disable_AAAA": True,
                "rate_limit": 30,
                "client_blacklist": [
                    "128.97.0.0"
                ]
            },

            "rules": {
                "force_safe_search": True,
                "hosts": {
                    "localhost": "127.0.0.1",
                    "cloudflare-dns.com": "1.0.0.1",
                    "dns.google": "8.8.4.4"
                }
            },

            "inbounds": [
                "0.0.0.0:53",
                "tcp://0.0.0.0:5301"
            ],

            "outbounds": [
                {
                    "tag": "bootstrap",
                    "dns": ["1.0.0.1"],
                    "domains": [
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
                    "tag": "void",
                    "dns": ["0.0.0.0"],
                    "concurrent": False,
                    "domains": [
                        "testvoid.com",
                        "include:testinclude",
                        "subdomain:testsub.com"
                    ]
                },
                {
                    "tag": "unencrypted",
                    "dns": ["1.0.0.1", "tcp://8.8.4.4"],
                    "concurrent": False,
                    "domains": ["sub:youtube.com", "include:netflix.com"],
                },
                {
                    "tag": "encrypted",
                    "dns": ["https://cloudflare-dns.com", "tls://dns.google"],
                    "concurrent": False,
                    "domains": ["all"]
                }
            ]
        }

        self.logger = logging.getLogger("encrypted_dns.ConfigHandler")
        self.config = {}
        self.file_name = configPathStr
        self.load()

    def check_format(self):
        return self

    def set_default_config(self):
        self.config = self.get_default_config()
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
            errMsg = "Failed to load config file. config file is not found in " + self.file_name + "."
            self.logger.error(errMsg)
            raise Exception(errMsg)
        else:
            config_file = open(self.file_name)
            self.config = json.loads(config_file.read())
            if self.config.get("version"):
                self.logger.info("Load config file: " + self.file_name)
            else:
                errMsg = "Failed to load config file. config file " + self.file_name + " is deprecated."
                self.logger.error(errMsg)
                raise Exception(errMsg)

    def save(self):
        file_init = os.path.isfile(self.file_name)
        if not file_init:
            errMsg = "Failed to save config file. config file is not found in " + self.file_name + "."
            self.logger.error(errMsg)
            raise Exception(errMsg)

        config_json = json.dumps(self.config, indent=4)
        config_file = open(self.file_name, "w")
        config_file.write(config_json)
