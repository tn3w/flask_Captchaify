"""
--- IP Utils ---

This module provides utility functions for handling IP addresses. It
provides methods for checking if an IP address is in a list of unwanted
IP ranges, and for reversing an IP address for DNS lookup.

Author:   tn3w (mail@tn3w.dev)
License:  Apache-2.0 license
"""

import re
import random
import socket
import urllib.error
import urllib.request
from urllib.parse import urlencode
from typing import Final, Optional
from datetime import datetime, timedelta

try:
    from utils.logger import log
    from utils.geoip import GeoIP, get_geoip
    from utils.utilities import http_request, cache_with_ttl
except ImportError:
    try:
        from src.flask_Captchaify.utils.logger import log
        from src.flask_Captchaify.utils.geoip import GeoIP, get_geoip
        from src.flask_Captchaify.utils.utilities import (
            http_request, cache_with_ttl
        )
    except ImportError:
        from logger import log
        from geoip import GeoIP, get_geoip
        from utilities import http_request, cache_with_ttl


UNWANTED_IPV4_RANGES: Final[list] = [
    ('0.0.0.0', '0.255.255.255'),
    ('10.0.0.0', '10.255.255.255'),
    ('100.64.0.0', '100.127.255.255'),
    ('127.0.0.0', '127.255.255.255'),
    ('169.254.0.0', '169.254.255.255'),
    ('172.16.0.0', '172.31.255.255'),
    ('192.0.0.0', '192.0.0.255'),
    ('192.0.2.0', '192.0.2.255'),
    ('192.88.99.0', '192.88.99.255'),
    ('192.168.0.0', '192.168.255.255'),
    ('198.18.0.0', '198.19.255.255'),
    ('198.51.100.0', '198.51.100.255'),
    ('203.0.113.0', '203.0.113.255'),
    ('224.0.0.0', '239.255.255.255'),
    ('233.252.0.0', '233.252.0.255'),
    ('240.0.0.0', '255.255.255.254'),
    ('255.255.255.255', '255.255.255.255')
]
UNWANTED_IPV6_RANGES: Final[list] = [
    ('::', '::'),
    ('::1', '::1'),
    ('::ffff:0:0', '::ffff:0:ffff:ffff'),
    ('64:ff9b::', '64:ff9b::ffff:ffff'),
    ('64:ff9b:1::', '64:ff9b:1:ffff:ffff:ffff:ffff'),
    ('100::', '100::ffff:ffff:ffff:ffff'),
    ('2001::', '2001:0:ffff:ffff:ffff:ffff:ffff:ffff'),
    ('2001:20::', '2001:2f:ffff:ffff:ffff:ffff:ffff:ffff'),
    ('2001:db8::', '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'),
    ('2002::', '2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
    ('5f00::', '5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
    ('fc00::', 'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
    ('fe80::', 'fe80::ffff:ffff:ffff:ffff'),
    ('ff00::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
]
IPV4_PATTERN: Final[str] = r'^(\d{1,3}\.){3}\d{1,3}$'
IPV6_PATTERN: Final[str] = r"""
    ^(
        ([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4} |
        ([0-9a-fA-F]{1,4}:){1,7}: |
        :(:[0-9a-fA-F]{1,4}){1,7} |
        ([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4} |
        ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2} |
        ([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3} |
        ([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4} |
        ([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5} |
        [0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6}) |
        :((:[0-9a-fA-F]{1,4}){1,7}|:) |
        ([0-9a-fA-F]{1,4}:){1,7}:
    )$
"""

COMPILED_IPV4_REGEX: Final[re.Pattern] = re.compile(IPV4_PATTERN, re.VERBOSE | re.IGNORECASE)
COMPILED_IPV6_REGEX: Final[re.Pattern] = re.compile(IPV6_PATTERN, re.VERBOSE | re.IGNORECASE)


def is_ipv4(ip_address: str) -> bool:
    """
    Checks whether the given IP address is version 4.

    Args:
        ip_address (str): The IP address to check.
    
    Returns:
        bool: True if the IP address is version 4, False otherwise.
    """

    if not isinstance(ip_address, str):
        return False

    return bool(COMPILED_IPV4_REGEX.match(ip_address))


def is_ipv6(ip_address: str) -> bool:
    """
    Checks whether the given IP address is version 6.

    Args:
        ip_address (str): The IP address to check.
    
    Returns:
        bool: True if the IP address is version 6, False otherwise.
    """

    if not isinstance(ip_address, str):
        return False

    return bool(COMPILED_IPV6_REGEX.match(ip_address))


def explode_ipv6(ipv6_address: str) -> str:
    """
    Explodes an IPv6 address.

    Args:
        ipv6_address (str): The IPv6 address to explode.
    
    Returns:
        str: The exploded IPv6 address.
    """

    groups = ipv6_address.split('::')
    if len(groups) > 2:
        return ipv6_address

    left_groups = groups[0].split(':')
    right_groups = groups[1].split(':') if len(groups) == 2 else []

    expanded_groups = []
    for group in left_groups:
        if group == '':
            expanded_groups.extend(['0000'] * (8 - len(left_groups) + 1))
        else:
            expanded_groups.append(group.zfill(4))

    for group in right_groups:
        expanded_groups.append(group.zfill(4))

    if len(groups) == 2:
        missing_groups = 8 - len(left_groups) - len(right_groups)
        if missing_groups < 0:
            return ipv6_address

        expanded_groups.extend(['0000'] * missing_groups)

    return ':'.join(expanded_groups)


def ipv4_to_int(ipv4_address: str) -> int:
    """
    Converts an IPv4 address to an integer.

    Args:
        ipv4_address (str): The IPv4 address to convert.
    
    Returns:
        int: The integer representation of the IPv4 address.
    """

    parts = map(int, ipv4_address.split('.'))
    return sum(part << (8 * (3 - i)) for i, part in enumerate(parts))


def ipv6_to_int(ipv6_address: str) -> int:
    """
    Converts an IPv6 address to an integer.

    Args:
        ipv6_address (str): The IPv6 address to convert.
    
    Returns:
        int: The integer representation of the IPv6 address.
    """

    parts = ipv6_address.split(':')
    parts = [int(part, 16) if part else 0 for part in parts]

    ip_int = 0
    for i, part in enumerate(parts):
        ip_int += part << (16 * (7 - i))

    return ip_int


def is_unwanted_ipv4(ipv4_address: Optional[str] = None) -> bool:
    """
    Checks whether the given IPv4 address is unwanted.

    Args:
        ipv4_address (str): The IPv4 address to check.

    Returns:
        bool: True if the IPv4 address is unwanted, False otherwise.
    """

    if not isinstance(ipv4_address, str):
        return False

    ipv4_address_int = ipv4_to_int(ipv4_address)

    for start_ip, end_ip in UNWANTED_IPV4_RANGES:
        start_ipv4_int = ipv4_to_int(start_ip)
        end_ipv4_int = ipv4_to_int(end_ip)

        if start_ipv4_int <= ipv4_address_int <= end_ipv4_int:
            return True

    return False


def is_unwanted_ipv6(ipv6_address: Optional[str] = None) -> bool:
    """
    Checks whether the given IPv6 address is unwanted.

    Args:
        ipv6_address (str): The IPv6 address to check.
    
    Returns:
        bool: True if the IPv6 address is unwanted, False otherwise.
    """

    if not isinstance(ipv6_address, str):
        return False

    ipv6_address_int = ipv6_to_int(ipv6_address)

    for start_ipv6, end_ipv6 in UNWANTED_IPV6_RANGES:
        start_ipv6_int = ipv6_to_int(start_ipv6)
        end_ipv6_int = ipv6_to_int(end_ipv6)

        if start_ipv6_int <= ipv6_address_int <= end_ipv6_int:
            return True

    return False


def is_valid_ip(ip_address: Optional[str] = None,
                without_filter: bool = False) -> bool:
    """
    Checks whether the given IP address is valid.

    Args:
        ip_address (str): The IP address to check.
        without_filter (bool): If True, the input IP address will not be filtered
    
    Returns:
        bool: True if the IP address is valid, False otherwise.
    """

    if not isinstance(ip_address, str):
        return False

    if not without_filter:
        is_ipv4_address = is_ipv4(ip_address)
        is_ipv6_address = is_ipv6(ip_address)

        if not is_ipv4_address and not is_ipv6_address:
            return False

        if (is_ipv4_address and is_unwanted_ipv4(ip_address)) or\
            (is_ipv6_address and is_unwanted_ipv6(ip_address)):

            return False

    if is_ipv4(ip_address):
        octets = ip_address.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True

    elif is_ipv6(ip_address):
        return True

    return False


def reverse_ip(ip_address: str) -> str:
    """
    Reverse the IP address for DNS lookup.

    Args:
        ip_address (str): The IP address to reverse.

    Returns:
        str: The reversed IP address.
    """

    symbol = ':' if ':' in ip_address else '.'
    return symbol.join(reversed(ip_address.split(symbol)))


MALICIOUS_ASNS: Final[str] = [
    "Fastly", "Incapsula", "Akamai", "AkamaiGslb", "Google", "Datacamp Limited",
    "Bing", "Censys", "Hetzner", "Linode", "Amazon", "AWS", "DigitalOcean", "Vultr",
    "Azure", "Alibaba", "Netlify", "IBM", "Oracle", "Scaleway", "Cloud", "VPN"
]


def is_asn_malicious(asn: str) -> bool:
    """
    Determines if a given Autonomous System Number (ASN) is considered malicious.

    Args:
        asn (str): The Autonomous System Number to check.

    Returns:
        bool: True if the ASN is not malicious, False if it is malicious.
    """

    normalized_asn = asn.lower().strip()

    for malicious_asn in MALICIOUS_ASNS:
        if malicious_asn.lower() in normalized_asn:
            return True

    return False


@cache_with_ttl(28800)
def is_ip_malicious_ipinfo(ip_address: str, api_key: Optional[str] = None) -> Optional[bool]:
    """
    Checks if a given IP address is malicious using the IPinfo.io API.

    Args:
        ip_address (str): The IP address to check.
        api_key (Optional[str]): The API key for authenticating with the IPinfo.io API.

    Returns:
        Optional[bool]: True if the IP address is malicious, False if it is not, or None
                        if the API key is not provided or an error occurs.
    """

    if api_key is None:
        return None

    url = f"https://ipinfo.io/{ip_address}?token=" + api_key
    data = http_request(url, is_json = True, default = {})

    some_data_provided = False
    for key in ["org", "asn", "privacy"]:
        value = data.get(key, None)
        if value is None:
            continue

        some_data_provided = True

        if key == "org":
            if is_asn_malicious(key):
                return True

            continue

        if key == "asn":
            if is_asn_malicious(value.get("name", "")):
                return True

            continue

        if key == "privacy":
            for privacy_key in ["vpn", "proxy", "tor", "relay", "hosting"]:
                privacy_value = value.get(privacy_key, None)
                if privacy_value is True:
                    return True

    if not some_data_provided:
        return None

    return False



@cache_with_ttl(28800)
def is_ip_malicious_ipapi(ip_address: str, api_key: Optional[str] = None) -> Optional[bool]:
    """
    Uses the IPApi.com API to check the reputation of the given IP address.

    Args:
        ip_address (str): The IP address to check.
        api_key (Optional[str]): The API key for authenticating with the IPApi.com API.
                                 If provided, it will be included in the request.

    Returns:
        Optional[bool]: True if the IP address is malicious, False if it is not, or None
                        if an error occurs.
    """

    url = f"http://ip-api.com/json/{ip_address}?fields=proxy,hosting"

    if api_key is not None:
        url += "&api_key=" + api_key
        url = url.replace("http", "https")

    data = http_request(url, is_json = True, default = {})

    some_data_provided = False
    for key in ["proxy", "hosting"]:
        value = data.get(key, None)
        if value is True:
            return True

        if value is not None:
            some_data_provided = True

    if not some_data_provided:
        return None

    return False


@cache_with_ttl(28800)
def is_ip_malicious_ipintel(ip_address: str, _: Optional[str] = None) -> Optional[bool]:
    """
    Uses the getipintel.net API to check the reputation of the given IP address.

    Args:
        ip_address (str): The IP address to check.

    Returns:
        Optional[bool]: True if the IP address is malicious, False otherwise.
    """

    random_email = ''.join(
        random.choice("abcdefghijklmnopqrstuvwxyz"
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                      for _ in range(random.randint(4, 9))) + '@outlook.com'

    url = f"https://check.getipintel.net/check.php?ip={ip_address}&contact={random_email}"

    data = http_request(url, default = "")
    if not data.isdigit():
        return None

    score = int(data)
    if score > 0.90:
        return True

    return False


@cache_with_ttl(28800)
def is_ip_malicious_stopforumspam(ip_address: str) -> bool:
    """
    Uses the stopforumspam.org API to check the reputation of the given IP address.

    Args:
        ip_address (str): The IP address to check.

    Returns:
        Optional[bool]: True if the IP address is malicious, False otherwise.
    """

    url = f'https://api.stopforumspam.org/api?ip={ip_address}&json'

    response_json = http_request(url, is_json = True, default = {})
    if not isinstance(response_json, dict):
        return False

    if not response_json.get('success') == 1:
        return False

    ip_info = response_json.get("ip", {})
    appears = ip_info.get("appears", 0)
    frequency = ip_info.get("frequency", 0)

    return appears >= 1 and frequency >= 2


@cache_with_ttl(28800)
def is_ip_malicious_geoip(ip_address: str) -> bool:
    """
    Checks the reputation of the given IP address using GeoIP databases.

    Args:
        ip_address (str): The IP address to check.

    Returns:
        bool: True if the IP address is found to be malicious.
    """

    geoip = get_geoip()

    some_database_available = False
    for db_name in ["asn", "anonymous"]:
        database: Optional[GeoIP] = geoip.get(db_name, None)
        if database is None:
            continue

        some_database_available = True

        ip_address_info = database.get(ip_address)
        if db_name == "asn":
            if is_asn_malicious(ip_address_info.get("asorg", "")):
                return True

        if db_name == "anonymous":
            if any(value for value in ip_address_info.values()):
                return True

    if not some_database_available:
        return None

    return False


def is_ip_malicious(ip_address: str, third_parties: Optional[list] = None) -> bool:
    """
    Checks whether the given IP address is malicious.

    Args:
        ip_address (str): The IP address to check.
        third_parties (Optional[list]): A list of third-party services to use for the check.

    Returns:
        bool: True if the IP address is malicious, False otherwise.
    """

    if not isinstance(ip_address, str):
        return False

    if third_parties is None:
        third_parties = ["ipapi", "ipintel", "stopforumspam", "geoip"]

    for third_party, third_party_function in {
            "ipinfo": is_ip_malicious_ipinfo,
            "ipapi": is_ip_malicious_ipapi,
            "ipintel": is_ip_malicious_ipintel,
            "stopforumspam": is_ip_malicious_stopforumspam,
        }.items():

        is_allowed = False
        for allowed_third_party in third_parties:
            if allowed_third_party.lower().startswith(third_party):
                is_allowed = True

        if not is_allowed:
            continue

        api_key = None
        if ":" in third_party:
            found_api_key = third_party.split(":")[1].strip()
            if len(found_api_key) > 1:
                api_key = found_api_key

        is_malicious = third_party_function(ip_address, api_key)
        if is_malicious is True:
            return True

    if "geoip" in third_parties:
        if is_ip_malicious_geoip(ip_address):
            return True

    return False


@cache_with_ttl(28800)
def is_ipv4_tor(ipv4_address: Optional[str] = None) -> bool:
    """
    Checks whether the given IPv4 address is Tor.

    Args:
        ipv4_address (str): The IPv4 address to check.

    Returns:
        bool: True if the IPv4 address is Tor, False otherwise.
    """

    query = reverse_ip(ipv4_address)

    try:
        resolved_ip = socket.gethostbyname(query)

        if resolved_ip == '127.0.0.2':
            return True

    except socket.gaierror:
        log(f"{ipv4_address} connection could not be established", level = 4)

    return False


@cache_with_ttl(28800)
def is_ip_tor_exonerator(ip_address: Optional[str] = None) -> bool:
    """
    Checks whether the given IP address is Tor using the Exonerator service.

    Args:
        ip_address (str): The IPv6 address to check.

    Returns:
        bool: True if the IPv6 address is Tor, False otherwise.
    """

    today = (datetime.now() - timedelta(days = 2)).strftime('%Y-%m-%d')

    base_url = "https://metrics.torproject.org/exonerator.html"
    query_params = {
        "ip": ip_address,
        "timestamp": today,
        "lang": "en"
    }
    url = f"{base_url}?{urlencode(query_params)}"

    req = urllib.request.Request(
        url, headers = {'Range': 'bytes=0-', "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            " (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.3"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout = 3) as response:
            html = ''
            while True:
                chunk = response.read(128).decode('utf-8')
                if not chunk:
                    break

                html += chunk
                if "Result is positive" in html:
                    return True

    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        log(f"{ip_address} connection could not be looked up on Exonerator", level = 4)

    return False


def is_ip_tor(ip_address: str, third_parties: Optional[list] = None) -> bool:
    """
    Checks whether the given IP address is Tor.

    Args:
        ip_address (str): The IP address to check.
        third_parties (Optional[list]): A list of third-party services to use for the check.
    Returns:
        bool: True if the IP address is Tor, False otherwise.
    """

    if not isinstance(ip_address, str):
        return False

    if third_parties is None:
        third_parties = ["tor_hostname", "tor_exonerator"]

    if "tor_hostname" in third_parties and is_ipv4(ip_address):
        if is_ipv4_tor(ip_address):
            return True

    if "tor_exonerator" in third_parties:
        if is_ip_tor_exonerator(ip_address):
            return True

    return False
