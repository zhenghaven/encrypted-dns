# Encrypted-DNS
[![License](https://img.shields.io/github/license/Siujoeng-Lau/Encrypted-DNS.svg?style=for-the-badge)](https://github.com/Siujoeng-Lau/Encrypted-DNS/blob/master/LICENSE)
[![Pull requests](https://img.shields.io/github/issues-pr-closed/Siujoeng-Lau/Encrypted-DNS?style=for-the-badge)](https://github.com/Siujoeng-Lau/Encrypted-DNS/pulls)
[![GitHub stars](https://img.shields.io/github/stars/Siujoeng-Lau/Encrypted-DNS?style=for-the-badge)](https://github.com/Siujoeng-Lau/Encrypted-DNS/stargazers)

Encrypted-DNS 是一个用于转发 DNS 请求的 DNS 服务器. 它支持 UDP, DNS-over-HTTPS, 以及 DNS-over-TLS 协议. 
它将会避免 DNS 污染和劫持, 缓存 DNS 请求, 屏蔽指定客户端, 以及对 DNS 进行分流.
   
语言: [English](https://github.com/Siujoeng-Lau/Encrypted-DNS/blob/master/README.md), [简体中文](https://github.com/Siujoeng-Lau/Encrypted-DNS/blob/master/README_zh.md).

### 安装

* 安装 [Python 3.7](https://www.python.org/downloads/).

* 克隆 Github 仓库.

```
$ git clone git@github.com:Siujoeng-Lau/Encrypted-DNS.git
```

* 运行 Encrypted-DNS 服务器.

```
$ cd Encrypted-DNS
$ sudo python3 main.py
```

* 测试 DNS 请求.

```
Linux or MacOS:
$ dig @127.0.0.1 www.google.com

Windows:
$ nslookup www.google.com 127.0.0.1
```

* 将设备的 DNS 地址改为 `127.0.0.1`.

### 配置

Encrypted-DNS 将会在程序目录中生成 JSON 格式的配置文件.

#### Upstream DNS (上游 DNS)

下面的 JSON 对象是一个典型的上游 DNS 配置.

Encrypted-DNS 支持以下协议: `plain`, `tls`, 和 `https`. 

你可以指定使用 DNS-over-HTTPS 和 DNS-over-TLS 协议的服务器的 IP 地址, 来避免 DNS 缓存污染.

```
{
    'protocol': 'tls',
    'address': 'dns.google',
    'ip': '8.8.4.4',
    'port': 853,
    'weight': 100
}
```

如果你指定了多个上游 DNS, Encrypted-DNS 将会对每一次请求采用"随机选择"或"加权随机选择"的方式来指定上游 DNS.

#### Bootstrap DNS Address (备用 DNS)

如果你没有指定 DNS-over-TLS 或 DNS-over-HTTPS 协议服务器的 IP 地址, Encrypted-DNS 将会向 Bootstrap DNS 服务器查询其对应地址.

```
'bootstrap_dns_address': {
    'address': '1.0.0.1',
    'port': 53
}
```

建议中国大陆的用户将其设置为位于中国境内的 DNS 服务器.

#### Client Blacklist (客户端黑名单)

Encrypted-DNS 将会屏蔽来自该列表内的 IP 地址的 DNS 请求.

```
'client_blacklist': [
    '1.0.0.1',
    '172.100.100.100'
]
```

#### DNS Bypass (绕过指定域名)

Encrypted-DNS 不会把对该列表内的域名的 DNS 请求转发至上游 DNS.

请求将会被转发到 Bootstrap DNS Address (备用 DNS 服务器).

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

#### DNS Bypass China (绕过中国大陆域名)

如果开启此功能, Encrypted-DNS 将会把对于中国大陆域名的请求转发至 Bootstrap DNS Address (备用 DNS 服务器), 而将其他地区的域名转发至上游. 

```
'dns_bypass_china': True
```

#### DNS Cache (DNS 缓存)

如果开启此功能, Encrypted-DNS 将会依据 `TTL` 对请求结果进行缓存, 减少下次查询的延迟.
```
'enable_cache': True
```
