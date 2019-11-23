# Encrypted-DNS
[![License](https://img.shields.io/github/license/Siujoeng-Lau/Encrypted-DNS.svg?style=for-the-badge)](https://github.com/Siujoeng-Lau/Encrypted-DNS/blob/master/LICENSE)
[![Pull requests](https://img.shields.io/github/issues-pr-closed/Siujoeng-Lau/Encrypted-DNS?style=for-the-badge)](https://github.com/Siujoeng-Lau/Encrypted-DNS/pulls)
[![GitHub stars](https://img.shields.io/github/stars/Siujoeng-Lau/Encrypted-DNS?style=for-the-badge)](https://github.com/Siujoeng-Lau/Encrypted-DNS/stargazers)

Encrypted-DNS operates as a DNS server that forward DNS queries over TLS or HTTPS, thus preventing your device from DNS cache poisoning and censorship.
It could also cache DNS records to accelerate further queries, block specific client, and ignore particular domain names.

### Usage

* Install [Python 3.7](https://www.python.org/downloads/)

* Clone Github Repository

```
$ git clone git@github.com:Siujoeng-Lau/Encrypted-DNS.git
```

* Run Encrypted-DNS Server

```
$ cd Encrypted-DNS
$ python3 main.py
```

* Test DNS Query

```
Linux or MacOS:
$ dig @127.0.0.1 www.google.com
Windows:
$ nslookup www.google.com 127.0.0.1
```

* Change DNS Server IP to 127.0.0.1

### Configure

Encrypted-DNS will generate a JSON file within its directory.

#### Upstream DNS

The following JSON dictionary is a typical Upstream DNS server.

Encrypted-DNS supports three protocols: `plain`, `tls`, and `https`. 

You may specify the ip address of DNS-over-HTTPS or DNS-over-TLS server to avoid DNS cache poisoning.

```
{
    'protocol': 'tls',
    'address': 'dns.google',
    'ip': '8.8.4.4',
    'port': 853,
    'weight': 100
}
```
If you add multiple address, DNS queries will be forwarded to a server based on random selection or weighted random selection.

#### Bootstrap DNS Address

Encrypted-DNS will send a plain DNS query to the bootstrap DNS server to retrieve the ip address of DNS-over-HTTPS or DNS-over-TLS server unless you specify it.
```
'bootstrap_dns_address': {
    'address': '1.0.0.1',
    'port': 53
}
```

#### Client Blacklist

You may set the ip addresses of the clients which you want to ignore DNS queries sent by them.
```
'client_blacklist': [
    '1.0.0.1',
    '172.100.100.100'
]
```

#### DNS Bypass

You may specify a list of domain names which you don't want to be forward to upstream DNS servers.

Queries will be sent to the bootstrap DNS server.

```
'dns_bypass': [
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
```

#### DNS Bypass China

If you set `dns_bypass_china` to `True`, all the queries related to domain names in China will be redirected to the bootstrap address, which could be set to a public DNS server located in China.

```
'dns_bypass_china': True
```

#### DNS Cache

If you set `enable_cache` to `True`, responses will be cached based on the TTL.

```
'enable_cache': True
```
