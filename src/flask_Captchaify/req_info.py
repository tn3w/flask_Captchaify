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
import json
import time
import shutil
import socket
import urllib.request
from urllib.parse import urlparse
from typing import Optional, Tuple, Union, Final
import dns.resolver
import geoip2.database
from werkzeug import Request
from .utils import PICKLE, DATA_DIR, ASSETS_DIR, handle_exception, get_domain_from_url


CACHE_FILE_PATH: Final[str] = os.path.join(DATA_DIR, 'cache.pkl')

UNWANTED_IPS: Final[list] = ['127.0.0.1', '192.168.0.1', '10.0.0.1',
                             '192.0.2.1', '198.51.100.1', '203.0.113.1']
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
        if ip_address in UNWANTED_IPS:
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


def reverse_ip(ip_address: str) -> str:
    """
    Reverse the IP address for DNS lookup.

    :param ip_address: Ipv4 or Ipv6 address.
    :return: The reversed IP address.
    """

    if is_ipv6(ip_address):
        ip_address = explode_ipv6(ip_address)

    return '.'.join(reversed(ip_address.split('.')))


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


class Cache(dict):
    """
    A dictionary-based cache that loads and saves data to a file using pickle.
    """


    def __init__(self, file_name: str, ttl: Optional[int] = None) -> None:
        """
        Initializes the Cache object.

        :param file_name: The name of the file to store cache data.
        :param ttl: The time to live in seconds, after that time data will be removed
                    from the cache.
        """

        self.file_name = file_name
        self.ttl = ttl

        super().__init__()


    def load(self, default: Optional[Union[dict, list]] = None) -> Union[dict, list]:
        """
        Loads and returns the cache data from the file.

        :param default: Returned if no data was found
        :return: The cache data from the file. If the cache file does not contain
                 data for this file_name, an empty dictionary is returned.
        """

        data = PICKLE.load(CACHE_FILE_PATH)

        if self.ttl is not None:
            now = time.time()
            data = {
                file_name: {key: value
                            for key, value in file_data.items()
                            if now - value[1] < self.ttl}
                for file_name, file_data in data.items()
            }

        return data.get(self.file_name, default)


    def __getitem__(self, key: any) -> any:
        """
        Retrieves the value associated with the given key from the cache.

        :param key: The key for which the value is to be retrieved.
        :return: The value associated with the key, or None if the key is not found.
        """

        data = self.load({}).get(self.file_name, {})
        return data.get(key, {}).get('value')


    def __setitem__(self, key: any, value: any) -> None:
        """
        Sets the value associated with the given key in the cache.

        :param key: The key for which the value is to be set.
        :param value: The value to be set for the key.
        """

        data = self.load(default={})

        if self.file_name not in data:
            data[self.file_name] = {}

        data[self.file_name][key] = (value, time.time())
        PICKLE.dump(data, CACHE_FILE_PATH)


    def __delitem__(self, key: any) -> None:
        """
        Deletes the value associated with the given key from the cache.

        :param key: The key for which the value is to be deleted.
        """

        data = self.load(default={})

        if self.file_name in data:
            del data[self.file_name][key]

        PICKLE.dump(data, CACHE_FILE_PATH)


class RequestInfo:
    """
    A class to handle various request-related information.
    """


    def __init__(self, request: Request, global_data: any,
                 languages: list, third_parties: list,
                 store_token: Optional[str] = None) -> None:
        """
        Initialize the RequestInfo class.

        :param request: The HTTP request object.
        :param global_data: Global data storage for the application.
        :param languages: A list of supported languages.
        :param third_parties: A list of third-party services.
        :param store_token: A token with which all data is saved in the global data.
        """

        self.request = request
        self.global_data = global_data
        self.languages = languages
        self.third_parties = third_parties

        if isinstance(store_token, str):
            self.store_token = store_token + '_'
            return

        self.store_token = ''


    def get_ip(self, return_all: bool = False) -> Optional[Union[str, list]]:
        """
        Retrieve the client's IP address.

        :param return_all: Flag to return all IP addresses if True.
        :return: The client's IP address or a list of IP addresses if return_all is True.
        """

        stored_ips = getattr(self.global_data, self.store_token + 'ips', [])

        if len(stored_ips) > 0:
            if return_all:
                return stored_ips
            return stored_ips[0]

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

        valid_ips = [ip for ip in ips if is_valid_ip(ip)]
        invalid_ips = [ip for ip in ips if is_valid_ip(ip, True)]

        if len(valid_ips) > 0:
            setattr(self.global_data, self.store_token + 'ips', valid_ips)

            if not return_all:
                return valid_ips[0]

            return valid_ips

        if not return_all and len(invalid_ips) > 0:
            return invalid_ips[0]

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
            if client_ip is None:
                return None

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
                    except Exception:
                        pass
                    else:
                        continue

                if field in ['as', 'as_code']:
                    try:
                        reader = geoip2.database.Reader(GEOLITE_DATA['as']['data_path'])
                        asn = reader.asn(client_ip)

                        stored_ip_info.update({
                            "as": asn.autonomous_system_organization,
                            "as_code": asn.autonomous_system_number,
                        })
                    except Exception:
                        pass
                    else:
                        continue

                if field == 'is_tor' and 'tor' in self.third_parties:
                    stored_ip_info["is_tor"] = self.is_tor(client_ip)
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
                             'as_code', 'reverse', 'mobile', 'proxy',
                             'hosting'] and\
                        'ipapi' in self.third_parties:
                    ipapi_data = self.get_ipapi_data()
                    if ipapi_data is not None:
                        stored_ip_info.update(ipapi_data)
                        continue

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


    def is_tor(self, client_ip: Optional[str] = None) -> bool:
        """
        Check if the client's IP is a Tor exit node.

        :param client_ip: The Ip address to be queried,
                          if not given this is the client IP.
        :return: True if the IP is a Tor exit node, False otherwise.
        """

        if client_ip is None:
            client_ip = self.get_ip()
            if client_ip is None:
                return False

        cache = Cache('tor')
        if cache[client_ip] is not None:
            return cache[client_ip]

        query = reverse_ip(client_ip)

        is_tor = False
        try:
            answers = dns.resolver.resolve(query, 'A')
            for rdata in answers:
                if rdata.to_text() == '127.0.0.2':
                    is_tor = True
                    break
        except Exception:
            pass

        cache[client_ip] = is_tor
        return is_tor


    def get_ipapi_data(self, client_ip: Optional[str] = None) -> dict:
        """
        Retrieve data from the IP-API service.

        :param client_ip: The Ip address to be queried,
                          if not given this is the client IP.
        :return: A dictionary with IP-API data.
        """

        if client_ip is None:
            client_ip = self.get_ip()
            if client_ip is None:
                return False

        cache = Cache('ipapi')
        if cache[client_ip] is not None:
            return cache[client_ip]

        url = f'http://ip-api.com/json/{client_ip}?fields=66846719'
        req = urllib.request.Request(url, headers = {"User-Agent": 'Mozilla/5.0'})

        try:
            with urllib.request.urlopen(req, timeout = 3) as response:
                response_data = response.read()

            response_json = json.loads(response_data)
        except Exception:
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
                as_code = value.split(' ')[0]
                as_org = ' '.join(value.split(' ')[1:])
                if not as_code.isdigit():
                    continue
                value = int(as_code)

            key = {'region': 'region_code', 'regionname':\
                   'region', 'as': 'as_code', 'asname': 'as'}\
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
            if client_ip is None:
                return False

        cache = Cache('forum_spammer')
        if cache[client_ip] is not None:
            return cache[client_ip]

        url = f'https://api.stopforumspam.org/api?ip={client_ip}&json'
        req = urllib.request.Request(url, headers={"User-Agent": 'Mozilla/5.0'})

        try:
            with urllib.request.urlopen(req, timeout = 3) as response:
                response_data = response.read()

            response_json = json.loads(response_data)
        except Exception:
            return None

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

        language = self.request.accept_languages\
                        .best_match(self.languages)
        if language is None:
            return default, True
        return language, True


    def get_without_cookies(self, cookies_disabled: bool = False) -> Tuple[bool, bool]:
        """
        Determine if the request should proceed without cookies.

        :param cookies_disabled: Flag indicating if cookies are disabled.
        :return: A tuple containing two boolean values.
        """

        if cookies_disabled:
            return True, True

        for arg in [self.request.args.get('wc'),
                      self.request.form.get('wc')]:
            if arg is not None:
                return arg == '1', False

        if self.request.cookies.get('cookieConsent') is not None:
            return self.request.cookies.get('cookieConsent') == '0', False

        if self.request.args.get('captcha') is not None:
            return True, False

        return False, True


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


def matches_rule(rule: list, req_info: RequestInfo) -> bool:
    """
    Recursively checks if client info matches a given rule.

    :param rule: The rule to be matched against the client info.
    :param req_info: The request info to be matched.
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

    info = client_info[field]

    try:
        if isinstance(operator, str):
            operator = operator.strip(' ')

        if operator in ('==', 'equals', 'equal', 'is'):
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
        if operator in ('greaterthan', 'largerthan'):
            return info > value
        if operator == 'lessthan':
            return info < value
        if operator in ('startswith', 'beginswith'):
            return info.startswith(value)
        if operator in ('endswith', 'concludeswith', 'finisheswith'):
            return info.endswith(value)
    except Exception as exc:
        handle_exception(exc, is_app_error=False)
        return False

    short_error_message = f'UnknownOperatorError: {operator} is not known.'
    handle_exception(
        short_error_message + '.', is_app_error=False, long_error_message=
        short_error_message + ' this is because you have specified an incorrect operator '
                             'field in the rules argument (valid: `==`, invalid: `is the same as`)'
    )
    return False
