"""
-~- RequestInfo Module -~-
This is a module to get extended client information
based on a Flask request object. It is part of the
flask_Captchaify module for Flask applications at
https://github.com/tn3w/flask_Captchaify.

The original GPL-3.0 licence applies.
"""

import re
import os
import shutil
import socket
import urllib.request
from urllib.parse import urlparse
from typing import Optional, Tuple, Union, Final
import dns.resolver
import geoip2.database
import crawleruseragents
from werkzeug import Request
from .utils import DATA_DIR, ASSETS_DIR, handle_exception, get_domain_from_url,\
    remove_duplicates, execute_write, type_or_none, read, request_url
from .cryptograph import Cache


OWN_IP_FILE_PATH: Final[str] = os.path.join(DATA_DIR, 'own_ip.txt')

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
IPV6_PATTERN: Final[str] = (
    r'^('
    r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|:'
    r'|::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}'
    r'|[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}'
    r'|([0-9a-fA-F]{1,4}:){1,2}:([0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}'
    r'|([0-9a-fA-F]{1,4}:){1,3}:([0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}'
    r'|([0-9a-fA-F]{1,4}:){1,4}:([0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}'
    r'|([0-9a-fA-F]{1,4}:){1,5}:([0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4}'
    r'|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
    r'|([0-9a-fA-F]{1,4}:){1,7}|:((:[0-9a-fA-F]{1,4}){1,7}|:)'
    r'|([0-9a-fA-F]{1,4}:)(:[0-9a-fA-F]{1,4}){1,7}'
    r'|([0-9a-fA-F]{1,4}:){2}(:[0-9a-fA-F]{1,4}){1,6}'
    r'|([0-9a-fA-F]{1,4}:){3}(:[0-9a-fA-F]{1,4}){1,5}'
    r'|([0-9a-fA-F]{1,4}:){4}(:[0-9a-fA-F]{1,4}){1,4}'
    r'|([0-9a-fA-F]{1,4}:){5}(:[0-9a-fA-F]{1,4}){1,3}'
    r'|([0-9a-fA-F]{1,4}:){6}(:[0-9a-fA-F]{1,4}){1,2}'
    r'|([0-9a-fA-F]{1,4}:){7}(:[0-9a-fA-F]{1,4}):)$'
)
ALL_REQUEST_INFO_FIELDS: Final[set] = [
    'continent', 'continent_code', 'country', 'country_code', 'region', 'region_code',
    'city', 'zip', 'lat', 'lon', 'as', 'as_number', 'tor', 'spammer', 'reverse',
    'timezone', 'offset', 'currency', 'isp', 'org', 'mobile', 'proxy', 'hosting'
]

GEOLITE_DATA: Final[dict] = {
    "city": {
        "url": "https://git.io/GeoLite2-City.mmdb",
        "data_path": os.path.join(DATA_DIR, "GeoLite2-City.mmdb"),
        "assets_path": os.path.join(ASSETS_DIR, "GeoLite2-City.mmdb")
    },
    "asn": {
        "url": "https://git.io/GeoLite2-ASN.mmdb",
        "data_path": os.path.join(DATA_DIR, "GeoLite2-ASN.mmdb"),
        "assets_path": os.path.join(ASSETS_DIR, "GeoLite2-ASN.mmdb")
    }
}


############################
#### IP Address Helpers ####
############################


def request_own_ip(debug: bool = False) -> Optional[str]:
    """
    Requests the own ip address.

    :param debug: Whether to throw error messages directly.
    :return: The local ip address.
    """

    own_ip = read(OWN_IP_FILE_PATH)
    if isinstance(own_ip, str):
        own_ip = own_ip.strip()
        if is_valid_ip(own_ip, True):
            return own_ip

    url = 'https://api64.ipify.org?format=json'

    try:
        response_json = request_url(url, debug = debug)
        if not isinstance(response_json, dict):
            return None

        if isinstance(response_json.get('ip', None), str):
            own_ip = response_json['ip'].strip()
            execute_write(OWN_IP_FILE_PATH, own_ip)

            return own_ip
    except Exception as exc:
        if debug:
            raise exc

        handle_exception(exc, False, False)

    return None


def is_ipv6(ip_address: str) -> bool:
    """
    Checks whether the given IP address is version 6.

    :param ip_address: The IP address to check.
    :return: True if the IP address is version 6, False otherwise.
    """

    ipv6_regex = re.compile(IPV6_PATTERN)
    return bool(ipv6_regex.match(ip_address))


def explode_ipv6(ip_address: str) -> str:
    """
    Explodes an IPv6 address.

    :param ip_address: The IPv6 address to compress.
    :return: The compressed IPv6 address.
    """

    groups = ip_address.split('::')
    if len(groups) > 2:
        return ip_address

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
            return ip_address

        expanded_groups.extend(['0000'] * missing_groups)

    return expanded_groups


def ipv4_to_int(ipv4_address: str) -> int:
    """
    Converts an IPv4 address to an integer.

    :param ip: IPv4 address
    :return: Integer representation of the IPv4 address
    """

    parts = map(int, ipv4_address.split('.'))
    return sum(part << (8 * (3 - i)) for i, part in enumerate(parts))


def ipv6_to_int(ipv6_address: str) -> int:
    """
    Converts an IPv6 address to an integer.

    :param ip: IPv6 address
    :return: Integer representation of the IPv6 address
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

    :param ipv4_address: IPv4 address (optional)
    :return: True if the IPv4 address is unwanted, False otherwise
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

    :param ipv6_address: IPv6 address (optional)
    :return: True if the IPv6 address is unwanted, False otherwise
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

    :param ip_address: IPv4 or IPv6 address (optional)
    :param without_filter: If True, the input IP address will not be filtered
    :return: True if the IP address is valid, False otherwise
    """

    if not isinstance(ip_address, str):
        return False

    if not without_filter:
        if is_ipv6(ip_address) and is_unwanted_ipv6(ip_address) or is_unwanted_ipv4(ip_address):
            return False

    ipv4_regex = re.compile(IPV4_PATTERN)
    ipv6_regex = re.compile(IPV6_PATTERN)

    if ipv4_regex.match(ip_address):
        octets = ip_address.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    elif ipv6_regex.match(ip_address):
        return True

    return False


def reverse_ip(ip_address: str) -> str:
    """
    Reverse the IP address for DNS lookup.

    :param ip_address: Ipv4 or Ipv6 address.
    :return: The reversed IP address.
    """

    if is_ipv6(ip_address):
        ip_address = explode_ipv6(ip_address)

        return ':'.join(reversed(ip_address))

    return '.'.join(reversed(ip_address.split('.')))


def is_tor(ip_address: Optional[str] = None, debug: bool = False) -> bool:
    """
    Check if an IP address is a Tor exit node.

    :param ip_address: The IP address to check.
    :param debug: Whether to print debug messages.
    :return: True if the IP address is a Tor exit node, False otherwise.
    """

    query = reverse_ip(ip_address)

    try:
        answers = dns.resolver.resolve(query, 'A')
        for rdata in answers:
            if rdata.to_text() == '127.0.0.2':
                return True
    except Exception as exc:
        if debug:
            raise exc

        handle_exception(exc, False, False)

    return False


###########################
#### Generic functions ####
###########################


def update_geolite_databases(allow_download: bool = True) -> None:
    """
    Downloads and updates GeoLite2 databases.

    :param allow_download: Flag indicating if the download should be allowed.
    :return: None
    """

    if not os.path.isdir(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)

    if allow_download:
        for database_data in GEOLITE_DATA.values():
            if not os.path.isfile(database_data['data_path']):
                urllib.request.urlretrieve(
                    database_data['url'],
                    database_data['data_path']
                )
        return

    for database_data in GEOLITE_DATA.values():
        if os.path.isfile(database_data['data_path']):
            continue

        if os.path.isfile(database_data['assets_path']):
            shutil.copyfile(
                database_data['assets_path'],
                database_data['data_path']
            )


def matches_asterisk_rule(obj: str, asterisk_rule: str) -> bool:
    """
    Check if a string matches an asterisk rule.

    :param obj: String to be checked.
    :param asterisk_rule: String containing '*' as wildcard character.
    :return: True if the string matches the asterisk rule, False otherwise.
    """

    if isinstance(obj, str) and isinstance(asterisk_rule, str) and '*' in asterisk_rule:
        parts = asterisk_rule.split('*')

        if len(parts) == 2:
            start, end = parts
            return obj.startswith(start) and obj.endswith(end)

        first_asterisk_index = asterisk_rule.index('*')
        last_asterisk_index = asterisk_rule.rindex('*')
        start = asterisk_rule[:first_asterisk_index]
        middle = asterisk_rule[first_asterisk_index + 1:last_asterisk_index]
        end = asterisk_rule[last_asterisk_index + 1:]

        return obj.startswith(start) and obj.endswith(end) and middle in obj

    return obj == asterisk_rule


def convert_string_to_int(string: str) -> int:
    """
    Convert a string to an integer.

    :param string: The string to be converted.
    :return: The integer representation of the string.
    """

    if not isinstance(string, str):
        return string

    string = string.strip()

    if string.lstrip('-').isdigit():
        return int(string)

    if string.endswith('-') and string[:-1].isdigit():
        return -int(string[:-1])

    return string


class RequestInfo:
    """
    A class to handle various request-related information.
    """


    def __init__(self, request: Request, global_data: any,
                 languages: list, third_parties: list,
                 store_token: Optional[str] = None,
                 store_anonymously: bool = True,
                 debug: bool = False) -> None:
        """
        Initialize the RequestInfo class.

        :param request: The HTTP request object.
        :param global_data: Global data storage for the application.
        :param languages: A list of supported languages.
        :param third_parties: A list of third-party services.
        :param store_token: A token with which all data is saved in the global data.
        :param store_anonymously: Whether to store the cache data anonymously.
        :param debug: Whether to print debug messages.
        """

        self.request = request
        self.global_data = global_data
        self.languages = languages
        self.third_parties = third_parties
        self.store_anonymously = store_anonymously
        self.debug = debug

        if isinstance(store_token, str):
            self.store_token = store_token + '_'
            return

        self.store_token = ''


    def get_user_agent(self) -> Optional[str]:
        """
        Retrieve the client's user agent.

        :return: The client's user agent.
        """

        user_agents = [
            self.request.user_agent.string,
            self.request.headers.get('User-Agent', None)
        ]

        for user_agent in user_agents:
            if isinstance(user_agent, str):
                return user_agent

        return None


    def get_ip(self, return_all: bool = False) -> Optional[Union[str, list]]:
        """
        Retrieve the client's IP address.

        :param return_all: Flag to return all IP addresses if True.
        :return: The client's IP address or a list of IP addresses if return_all is True.
        """

        stored_ips = getattr(self.global_data, self.store_token + 'ips', [])

        if len(stored_ips) > 0:
            if 'notfound' in stored_ips:
                return None if not return_all else []

            return stored_ips if return_all else stored_ips[0]

        ips = [
            self.request.remote_addr,
            self.request.environ.get('HTTP_X_REAL_IP', None),
            self.request.environ.get('REMOTE_ADDR', None),
            self.request.environ.get('HTTP_X_FORWARDED_FOR', None),
            self.request.environ.get('HTTP_CF_CONNECTING_IP', None),
            self.request.headers.get('X-Forwarded-For', None),
            self.request.headers.get('X-Real-Ip', None),
            self.request.headers.get('True-Client-Ip', None),
            self.request.headers.get('CF-Connecting-IP', None),
            self.request.headers.get('X-Appengine-User-Ip', None)
        ]

        valid_ips = remove_duplicates([ip for ip in ips if is_valid_ip(ip)])
        invalid_ips = remove_duplicates([ip for ip in ips if is_valid_ip(ip, True)])

        for ips in [valid_ips, invalid_ips]:
            if len(ips) == 0:
                continue

            return_ip = ips if return_all else ips[0]

            if return_ip == '127.0.0.1' and 'ipify' in self.third_parties:
                return_ip = request_own_ip(self.debug)
                setattr(self.global_data, self.store_token + 'ips', [return_ip])
            else:
                setattr(self.global_data, self.store_token + 'ips', ips)

            return return_ip

        setattr(self.global_data, self.store_token + 'ips', ['notfound'])
        return None if not return_all else []


    def get_ip_info(self, fields: list, client_ip:\
                    Optional[str] = None) -> Optional[Union[dict, str]]:
        """
        Retrieve information about the client's IP address.

        :param fields: A list of fields to retrieve information for.
        :param client_ip: The Ip address to be queried,
                          if not given this is the client IP.
        :return: A dictionary of IP information or None.
        """

        if client_ip is None:
            client_ip = self.get_ip()

        if not is_valid_ip(client_ip):
            return None

        if 'full' in fields:
            fields = ALL_REQUEST_INFO_FIELDS

        stored_ip_info = getattr(self.global_data, self.store_token + 'ip_info', {})

        information = {}

        for field in fields:
            i = 0
            while True:
                if field in stored_ip_info:
                    break

                if field in ['continent', 'continent_code', 'country',
                            'country_code', 'region', 'region_code',
                            'city', 'zip', 'lat', 'lon']:

                    try:
                        reader = geoip2.database.Reader(GEOLITE_DATA['city']['data_path'])
                        loc = reader.city(client_ip)
                        stored_ip_info.update({
                            "continent": loc.continent.name,
                            "continent_code": loc.continent.code,
                            "country": loc.country.name,
                            "country_code": loc.country.iso_code,
                            "region": loc.subdivisions.most_specific.name,
                            "region_code": loc.subdivisions.most_specific.iso_code,
                            "city": loc.city.name,
                            "zip": loc.postal.code,
                            "lat": loc.location.latitude,
                            "lon": loc.location.longitude
                        })
                    except Exception as exc:
                        if self.debug:
                            raise exc

                        handle_exception(exc, False, False)
                    else:
                        continue

                if field in ['as', 'as_number']:
                    try:
                        reader = geoip2.database.Reader(GEOLITE_DATA['asn']['data_path'])
                        asn = reader.asn(client_ip)

                        stored_ip_info.update({
                            "as": asn.autonomous_system_organization,
                            "as_number": asn.autonomous_system_number,
                        })
                    except Exception as exc:
                        if self.debug:
                            raise exc

                        handle_exception(exc, False, False)
                    else:
                        continue

                if field == 'tor' and 'tor' in self.third_parties:
                    stored_ip_info["tor"] = self.is_tor(client_ip)
                    break

                if field == 'reverse' and 'reverse' in self.third_parties:
                    socket.setdefaulttimeout(1)
                    reverse = socket.gethostbyaddr(client_ip)[0]
                    if not reverse == client_ip:
                        stored_ip_info["reverse"] = reverse

                if field in 'spammer' and 'stopforumspam' in self.third_parties:
                    stored_ip_info["spammer"] = self.is_spammer(client_ip)
                    break

                if field in ['continent', 'continent_code', 'country',
                             'country_code', 'region', 'region_code',
                             'city', 'zip', 'lat', 'lon', 'timezone',
                             'offset', 'currency', 'isp', 'org', 'as',
                             'as_number', 'reverse', 'mobile', 'proxy',
                             'hosting'] and\
                        'ipapi' in self.third_parties:

                    ipapi_data = self.get_ipapi_data()
                    if ipapi_data is not None and field in ipapi_data:
                        stored_ip_info.update(ipapi_data)
                        break

                i += 1
                if i > 1:
                    information[field] = None
                    break

        for key, value in stored_ip_info.items():
            if key in fields:
                information[key] = value

        setattr(self.global_data, '_ip_info', stored_ip_info)

        if len(fields) == 1:
            return information[fields[0]]

        return information


    def is_crawler(self, user_agent: Optional[str] = None) -> bool:
        """
        Check if the user agent is a crawler.

        :param user_agent: The user agent to be checked.
        :return: True if the user agent is a crawler, False otherwise.
        """

        if isinstance(getattr(self.global_data, self.store_token + 'is_crawler', None), bool):
            return getattr(self.global_data, self.store_token + 'is_crawler')

        if user_agent is None:
            user_agent = self.get_user_agent()

        if user_agent is None:
            return False

        is_crawler = crawleruseragents.is_crawler(user_agent)

        setattr(self.global_data, self.store_token + 'is_crawler', is_crawler)
        return is_crawler


    def is_tor(self, client_ip: Optional[str] = None) -> bool:
        """
        Check if the client's IP is a Tor exit node.

        :param client_ip: The Ip address to be queried,
                          if not given this is the client IP.
        :return: True if the IP is a Tor exit node, False otherwise.
        """

        if client_ip is None:
            client_ip = self.get_ip()

        if not is_valid_ip(client_ip):
            return False

        cache = Cache('tor', store_anonymously = self.store_anonymously, debug = self.debug)
        if cache[client_ip] is not None:
            return cache[client_ip]

        is_tor_ip = is_tor(client_ip, self.debug)

        cache[client_ip] = is_tor_ip
        return is_tor_ip


    def get_ipapi_data(self, client_ip: Optional[str] = None) -> dict:
        """
        Retrieve data from the IP-API service.

        :param client_ip: The Ip address to be queried,
                          if not given this is the client IP.
        :return: A dictionary with IP-API data.
        """

        if client_ip is None:
            client_ip = self.get_ip()

        if not is_valid_ip(client_ip):
            return None

        cache = Cache('ipapi', store_anonymously = self.store_anonymously, debug = self.debug)
        if cache[client_ip] is not None:
            return cache[client_ip]

        url = f'http://ip-api.com/json/{client_ip}?fields=66846719'

        response_json = request_url(url, debug = self.debug)
        if not isinstance(response_json, dict):
            return None

        if not response_json.get('status') == 'success':
            cache[client_ip] = None
            return None

        del response_json['status'], response_json['query']

        ipapi_data = {}
        as_org = None
        for key, value in response_json.items():
            if key == 'org' and value.strip() == '':
                if as_org is not None:
                    value = as_org
                else:
                    as_value = response_json.get('as', None)
                    if isinstance(as_value, str) and as_value.strip() != '':
                        value = ' '.join(as_value.split(' ')[1:])

            if key == 'as' and isinstance(value, str):
                as_number = value.split(' ')[0]
                as_org = ' '.join(value.split(' ')[1:])
                if not as_number.isdigit():
                    continue

                value = convert_string_to_int(as_number)

            if key == 'offset':
                value = convert_string_to_int(value)

            key = {'region': 'region_code', 'regionname':\
                   'region', 'as': 'as_number', 'asname': 'as'}\
                   .get(key.lower(), re.sub('([A-Z])', r'_\1', key).lower())
            ipapi_data[key] = value

        cache[client_ip] = ipapi_data
        return ipapi_data


    def is_spammer(self, client_ip: Optional[str] = None) -> bool:
        """
        Check if a IP is a spammer.
        
        :param client_ip: The Ip address to be queried,
                          if not given this is the client IP.
        :return: Whether the IP is identified as a spammer.
        """

        if client_ip is None:
            client_ip = self.get_ip()

        if not is_valid_ip(client_ip):
            return False

        cache = Cache(
            'forum_spammer', store_anonymously =\
            self.store_anonymously, debug = self.debug
        )

        if cache[client_ip] is not None:
            return cache[client_ip]

        url = f'https://api.stopforumspam.org/api?ip={client_ip}&json'

        response_json = request_url(url, debug = self.debug)
        if not isinstance(response_json, dict):
            return False

        if not response_json.get('success') == 1:
            cache[client_ip] = None
            return None

        is_spammer = False
        if response_json.get('ip', None) is not None:
            if response_json['ip'].get('appears') is not None:
                if response_json['ip']['appears'] > 0:
                    is_spammer = True

        cache[client_ip] = is_spammer
        return is_spammer


    def get_theme(self, without_customisation: bool = False,
                  default: str = 'light') -> Tuple[Optional[str], bool]:
        """
        Retrieve the theme setting.

        :param without_customisation: Flag to allow theme customization.
        :param default: The default theme if none is set.
        :return: A tuple containing the theme and a
                 boolean indicating if the default theme is used.
        """

        stored_theme = getattr(self.global_data, self.store_token + 'theme', None)
        if isinstance(stored_theme, str):
            return stored_theme, False

        theme = None
        if not without_customisation:
            theme_from_args = self.request.args.get('theme')
            theme_from_cookies = self.request.cookies.get('theme')
            theme_from_form = self.request.form.get('theme')

            theme = (
                theme_from_args
                if theme_from_args in ['light', 'dark']
                else (
                    theme_from_cookies
                    if theme_from_cookies in ['light', 'dark']
                    else (
                        theme_from_form
                        if theme_from_form in ['light', 'dark']
                        else None
                    )
                )
            )

        if theme is None:
            return default, True

        setattr(self.global_data, self.store_token + 'theme', theme)
        return theme, False


    def get_language(self, without_customisation: bool = False,
                     default: str = 'en') -> Tuple[Optional[str], bool]:
        """
        Retrieve the language setting.

        :param without_customisation: Flag to allow language customization.
        :param default: The default language if none is set.
        :return: A tuple containing the language and a
                 boolean indicating if the default language is used.
        """

        stored_language = getattr(self.global_data, self.store_token + 'lang', None)
        if isinstance(stored_language, str):
            return stored_language, False

        if not without_customisation:
            language_from_args = self.request.args.get('language')
            language_from_cookies = self.request.cookies.get('language')
            language_from_form = self.request.form.get('language')

            set_language = (
                language_from_args
                if language_from_args in self.languages
                else (
                    language_from_cookies
                    if language_from_cookies in self.languages
                    else (
                        language_from_form
                        if language_from_form in self.languages
                        else None
                    )
                )
            )

            if not set_language is None:
                setattr(self.global_data, self.store_token + 'lang', set_language)
                return set_language, False

        language = self.request.accept_languages.best_match(self.languages)

        return type_or_none(language, str, default), True


    def get_without_cookies(self, without_cookies: bool = False) -> Tuple[bool, bool]:
        """
        Determine if the request should proceed without cookies.

        :param without_cookies: Flag indicating if cookies are disabled.
        :return: A tuple containing two boolean values.
        """

        if without_cookies:
            return True, True

        for data in [self.request.args, self.request.form]:
            if not isinstance(data.get('wc'), str):
                continue

            return data.get('wc') == '1', False

        if self.request.cookies.get('cookieConsent') is not None:
            return self.request.cookies.get('cookieConsent') == '0', False

        for data in [self.request.args, self.request.cookies]:
            if not isinstance(data.get('captcha'), str):
                continue

            return data == self.request.args, False

        if self.request.args.get('captcha') is not None:
            return True, False

        return True, True


    def get_url(self) -> str:
        """
        Retrieve the full URL of the request.

        :return: The full URL as a string.
        """

        scheme = self.request.headers.get('X-Forwarded-Proto', '')
        if scheme not in ['https', 'http']:
            if self.request.is_secure:
                scheme = 'https'
            else:
                scheme = 'http'

        return scheme + '://' + self.request.url.split('://')[1]


def matches_rule(rule: list, req_info: RequestInfo, debug: bool = False) -> bool:
    """
    Recursively checks if client info matches a given rule.

    :param rule: The rule to be matched against the client info.
    :param req_info: The request info to be matched.
    :param debug: Flag indicating if debug mode is enabled.
    :return: True if client info matches the rule, False otherwise.
    """

    i = 0
    while i < len(rule):
        if rule[i] == 'and':
            return matches_rule(rule[:i], req_info) and \
                matches_rule(rule[i+1:], req_info)

        if rule[i] == 'or':
            return matches_rule(rule[:i], req_info) or \
                matches_rule(rule[i+1:], req_info)

        i += 1

    field, operator, value = rule

    current_url = req_info.get_url()

    url_info = urlparse(current_url)
    client_info = {
        "netloc": url_info.netloc, "hostname": url_info.hostname, 
        "domain": get_domain_from_url(current_url), "path": url_info.path,
        "endpoint": req_info.request.endpoint, "scheme": url_info.scheme,
        "url": current_url
    }

    if field not in client_info:
        client_info[field] = req_info.get_ip_info([field])

    try:
        info = client_info.get(field)
        if info is None:
            return False

        if isinstance(operator, str):
            operator = operator.strip(' ').lower()

        if operator in ('==', 'equals', 'equal', 'is', 'isthesameas'):
            return matches_asterisk_rule(info, value)
        if operator in ('!=', 'doesnotequal', 'doesnotequals', 'notequals', 'notequal', 'notis'):
            return not matches_asterisk_rule(info, value)

        if operator in ('contains', 'contain'):
            return value in info
        if operator in ('doesnotcontain', 'doesnotcontains', 'notcontain', 'notcontains'):
            return value not in info

        if operator in ('isin', 'in'):
            return info in value
        if operator in ('isnotin', 'notisin', 'notin'):
            return info not in value

        if operator in ('greaterthan', 'largerthan', 'lessthan'):
            if isinstance(info, str) and info.is_digit():
                info = int(info)
            elif not isinstance(info, int):
                return False

            if operator == 'lessthan':
                return info < value

            return info > value

        if operator in ('startswith', 'beginswith', 'endswith', 'concludeswith', 'finisheswith'):
            if isinstance(info, int):
                info = str(info)
            elif not isinstance(info, str):
                return False

            if operator in ('startswith', 'beginswith'):
                return info.startswith(value)

            return info.endswith(value)

    except Exception as exc:
        if debug:
            raise exc

        handle_exception(exc, is_app_error=False)
        return False

    if debug:
        raise ValueError(f'UnknownOperatorError: {operator} is not known. '+\
                        'This is because you have specified an incorrect '+\
                        'operator field in the rules argument.')

    short_error_message = f'UnknownOperatorError: {operator} is not known.'
    handle_exception(
        short_error_message + '.', is_app_error = False, long_error_message =
        short_error_message + (' This is because you have specified an incorr'
                               'ect operator field in the rules argument.')
    )
    return False
