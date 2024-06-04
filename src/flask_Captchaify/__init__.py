"""
-~- flask_Captchaify -~-
https://github.com/tn3w/flask_Captchaify
Made with 💩 in Germany by TN3W

This Flask library provides a way to integrate captchas,
known as a `fully automated public Turing test to distinguish computers from humans`,
in front of websites or specific pages. A captcha is a security mechanism that aims to
distinguish automated bots from real human users.

Under the open source license GPL-3.0 license, supported by Open Source Software
"""

import os
import re
import random
import secrets
import socket
from typing import Optional, Final, Union, Tuple
from time import time
from urllib.parse import urlparse, quote
from base64 import b64encode
import geoip2.database
import crawleruseragents
from bs4 import BeautifulSoup
from captcha.image import ImageCaptcha
from captcha.audio import AudioCaptcha
from flask import Flask, Response, request, g, abort, send_file, make_response, redirect
from .utils import JSON, PICKLE, Hashing, SymmetricCrypto, SSES, WebPage, get_work_dir,\
    get_client_ip, generate_random_string, get_ip_info, remove_args_from_url, is_tor_ip,\
    render_template, is_stopforumspam_spammer, search_languages, get_random_image,\
    manipulate_image_bytes, convert_image_to_base64, get_return_path, get_return_url,\
    extract_path_and_args, rearrange_url, handle_exception, does_match_rule, download_geolite,\
    get_domain_from_url


WORK_DIR: Final[str] = get_work_dir()
DATA_DIR: Final[str] = os.path.join(WORK_DIR, 'data')

if not os.path.isdir(DATA_DIR):
    os.makedirs(DATA_DIR, exist_ok = True)

ASSETS_DIR: Final[str] = os.path.join(WORK_DIR, 'assets')
TEMPLATE_DIR: Final[str] = os.path.join(WORK_DIR, 'templates')
DATASETS_DIR: Final[str] = os.path.join(WORK_DIR, 'datasets')

DATASET_PATHS: Final[dict] = {
    'default': os.path.join(DATASETS_DIR, 'keys.json'),
    'oneclick_keys': os.path.join(DATASETS_DIR, 'keys.json'),
    'multiclick_keys': os.path.join(DATASETS_DIR, 'keys.json'),
    'oneclick_animals': os.path.join(DATASETS_DIR, 'animals.json'),
    'multiclick_animals': os.path.join(DATASETS_DIR, 'animals.json'),
}

RATE_LIMIT_PATH: Final[str] = os.path.join(DATA_DIR, 'rate-limits.pkl')
FAILED_CAPTCHAS_PATH: Final[str] = os.path.join(DATA_DIR, 'failed-captchas.pkl')
SOLVED_CAPTCHAS_PATH: Final[str] = os.path.join(DATA_DIR, 'solved-captchas.pkl')
GEOLITE_DATA: Final[dict] = {
    "city": {
        "url": "https://git.io/GeoLite2-City.mmdb",
        "path": os.path.join(DATA_DIR, "GeoLite2-City.mmdb")
    },
    "asn": {
        "url": "https://git.io/GeoLite2-ASN.mmdb",
        "path": os.path.join(DATA_DIR, "GeoLite2-ASN.mmdb")
    }
}

EMOJIS: Final[list] = JSON.load(os.path.join(ASSETS_DIR, 'emojis.json'), [])
TEA_EMOJIS: Final[list] = JSON.load(os.path.join(ASSETS_DIR, 'tea_emojis.json'), [])
LANGUAGES: Final[list] = JSON.load(os.path.join(ASSETS_DIR, 'languages.json'), [])
LANGUAGE_CODES: Final[list] = [language['code'] for language in LANGUAGES]

ALL_CAPTCHA_TYPES: Final[list] = [
    'text', 'audio', 'oneclick_keys', 'multiclick_keys',
    'oneclick_animals', 'multiclick_animals', 'text&audio',
    'audio&text'
]
DATASET_SIZES: Final[dict] = {
    'largest': (200, 140),
    'large': (20, 140),
    'medium': (100, 100),
    'normal': (20, 100),
    'small': (20, 36),
    'smaller': (20, 8),
    'little': (6, 8)
}
ALL_ACTIONS: Final[list] = ['allow', 'block', 'fight', 'captcha']
ALL_THIRD_PARTIES: Final[list] = ['geoip', 'tor', 'ipapi', 'stopforumspam']
ALL_TEMPLATE_TYPES: Final[list] = [
    'captcha_text_audio', 'captcha_multiclick', 'captcha_oneclick',
    'captcha_trueclick', 'block', 'rate_limited', 'change_language'
]
ALL_THEMES: Final[list] = ['dark', 'light']


class Captchaify:
    """
    Shows the user/bot a captcha before the request first if the request comes from a dangerous IP
    Further function are: Rate Limits, Crawler Hints, Custom Templates, Rules for Specific Routes
    """

    def __init__ (
        self, app: Flask, rules: Optional[list[dict]] = None,
        dataset_size: Union[tuple[int], str] = 'normal', dataset_dir: Optional[str] = None,
        default_captcha_type: str = 'oneclick', default_action: str = 'captcha',
        default_rate_limit: Optional[int] = 120, default_max_rate_limit = 1200,
        default_template_dir: Optional[str] = None, verification_age: int = 3600,
        without_cookies: bool = False, block_crawler: bool = True,
        crawler_hints: bool = True, third_parties: Optional[list] = None,
        as_route: bool = False, without_other_args: Optional[bool] = True,
        allow_customization: bool = False, enable_trueclick: bool = False) -> None:
        """
        Configures security settings for a Flask app.

        :param app: Your Flask App.
        :param rules: Dict with rules and actions that occur in certain cases.
                      Example: {["ip", "==", "8.8.8.8"]: {"action": "block"}}
        :param dataset_size: Tuple containing the number of images of each keyword and the
                             number of keywords or a string with predefined sizes.
        :param dataset_dir: Where the datasets are located, default datasets are
                            stored in the default dataset folder.
        :param default_captcha_type: Default value of all pages if no special captcha type is given.
        :param default_action: Default value of all pages if no special action is given
                               in actions. Default is "captcha".
        :param default_rate_limit: How many requests an ip can make per minute,
                                   if nothing is given at rate_limits this value is used.
                                   If None, no rate limit is set. Default is 120.
        :param default_max_rate_limit: How many requests all Ips can make per minute,
                                       if nothing is given at rate_limits this value is used.
                                       If None, no max rate limit is set. Default is 1200.
        :param default_template_dir: Default value of all pages if no special template_dir is
                                     given in template_dirs. Default is None.
        :param verification_age: How long the captcha verification is valid, in seconds.
                                 Default is 3600 (1 hour).
        :param without_cookies: If True, no cookie is created after the captcha is fulfilled,
                                but only an Arg is appended to the URL. Default is False.
        :param block_crawler: If True, known crawlers based on their user agent will also
                              need to solve a captcha. Default is False.
        :param crawler_hints: If True, crawlers will cache a page with no content only with
                              meta content of the real web page that is already in the cache. 
                              Default is False.
        :param third_parties: List of third parties that are also used. All are used by default.
        :param as_route: Whether the captcha page has its own route and users who need a captcha
                         are redirected, especially for pages whose cache stores all pages
                         (e.g. Cloudflare).
        :param without_other_args: After solving the captcha, delete args like language or theme
                                   from the URL
        :param allow_customization: Allow the user to change their language and theme (can allow
                                    DDOS attacks on flask_Captchaify websites like Change Language)
        """

        if app is None:
            handle_exception(
                'No Flask app has been saved, which means that your own'+
                ' routes and endpoints are not visible.', is_app_error = False
            )
            app = Flask(__name__)

        if default_captcha_type == 'oneclick':
            default_captcha_type = 'oneclick_keys'
        elif default_captcha_type == 'multiclick':
            default_captcha_type = 'multiclick_animals'

        if isinstance(dataset_size, str):
            self.max_dataset_images, self.max_dataset_keys =\
                DATASET_SIZES.get(dataset_size, (20, 100))
        elif isinstance(dataset_size, tuple):
            self.max_dataset_images, self.max_dataset_keys = dataset_size
        else:
            self.max_dataset_images = 20
            self.max_dataset_keys = 100

        self.app = app
        self.rules = rules if isinstance(rules, list) else []
        self.dataset_dir = dataset_dir if isinstance(dataset_dir, str) else None
        self.default_captcha_type = default_captcha_type if default_captcha_type\
                                    in ALL_CAPTCHA_TYPES else 'default'
        self.default_action = default_action if default_action in ALL_ACTIONS else 'captcha'
        self.default_rate_limit = default_rate_limit if isinstance(default_rate_limit, int)\
                                  or default_rate_limit is None else 120
        self.default_max_rate_limit = default_max_rate_limit\
                                      if isinstance(default_max_rate_limit, int)\
                                      or default_max_rate_limit is None else 1200
        self.default_template_dir = default_template_dir if default_template_dir is not None\
                                    else TEMPLATE_DIR

        self.verification_age = verification_age if isinstance(verification_age, int) else 3600
        self.without_cookies = without_cookies if isinstance(without_cookies, bool) else False
        self.block_crawler = block_crawler if isinstance(block_crawler, bool) else True
        self.crawler_hints = crawler_hints if isinstance(crawler_hints, bool) else True
        self.third_parties = third_parties if isinstance(third_parties, list) else ALL_THIRD_PARTIES
        self.as_route = as_route if isinstance(as_route, bool) else False
        self.without_other_args = without_other_args if isinstance(without_other_args, bool)\
                                  else True
        self.allow_customization = allow_customization if isinstance(allow_customization, bool)\
                                   else False
        self.enable_trueclick = enable_trueclick if isinstance(enable_trueclick, bool) else False

        captcha_secret = generate_random_string(32)
        self.captcha_secret = captcha_secret

        self.sses = SSES(captcha_secret, with_keys = True)

        if 'geoip' in self.third_parties:
            download_geolite()

        if self.crawler_hints:
            self.crawler_hints_cache = {}

        self.used_captcha_ids = {}
        self.loaded_datasets = {}

        app.before_request(self._set_client_information)

        self.route_id = None
        if self.as_route:
            route_id = generate_random_string(6, False)
            self.route_id = route_id

            @app.route('/blocked-' + route_id)
            def blocked_captchaify() -> Response:
                """
                Render a block page with a captcha challenge.

                :return: A Flask response object.
                """

                return_path = get_return_path(request)
                if return_path is None:
                    return_path = '/'

                return_url = get_return_url(return_path, request)

                emoji = random.choice(EMOJIS)
                return self._correct_template(
                    'block', emoji = emoji, return_path = return_path,
                    return_url = return_url, route_id = self.route_id
                )

            @app.route('/rate_limited-' + route_id)
            def rate_limited_captchaify() -> Tuple[Response, int]:
                """
                Render a rate-limited page with a captcha challenge.

                :return: A tuple containing a Flask response object and an HTTP status code 429.
                """

                return_path = get_return_path(request)
                if return_path is None:
                    return_path = '/'

                return_url = get_return_url(return_path, request)

                emoji = random.choice(TEA_EMOJIS)
                return self._correct_template(
                    'rate_limited', emoji = emoji, return_path = return_path,
                    return_url = return_url, route_id = self.route_id
                ), 429

            @app.route('/captcha-' + route_id, methods = ['GET', 'POST'])
            @app.route('/captcha-' + route_id + '/', methods = ['GET', 'POST'])
            def captcha_captchaify() -> Response:
                """
                Handle requests for captcha verification.

                Workflow:
                1. Retrieve the return path from the request or set it to '/' if not provided.
                2. Check for too many attempts and redirect to the block page if necessary.
                3. Validate the captcha token and redirect based on its validity.
                4. Handle additional URL parameters and manage cookies as needed.
                5. Display the captcha challenge if validation fails.
                6. Handle exceptions and redirect to the blocked page if an error occurs.

                :return: A Flask response object.
                """

                try:
                    return_path = get_return_path(request)
                    if return_path is None:
                        return_path = '/'

                    client_ip = self.ip

                    preferences = self._preferences
                    action = preferences['action']

                    if self._to_many_attempts(action):
                        g.captchaify_page = True
                        return redirect(self._create_route_url('block'))

                    is_valid_ct, is_failed_captcha = self._is_ct_valid()
                    if is_valid_ct:
                        return self._valid_captcha(return_path)

                    if self._is_captcha_verifier_valid():
                        return_url = get_return_url(return_path, request)
                        if '?' not in return_url:
                            char = '?'
                        else:
                            char += '&'

                        captcha_string = None
                        if request.args.get('captcha') is not None:
                            captcha_string = request.args.get('captcha')
                        elif request.cookies.get('captcha') is not None:
                            captcha_string = request.cookies.get('captcha')

                        if self._without_cookies[0] and captcha_string is not None:
                            return_url += char + 'captcha=' + captcha_string

                        if not self.without_other_args:
                            theme, is_default_theme = WebPage.client_theme(request)
                            language, is_default_language = WebPage.client_language(request)
                            without_cookies, is_default_choice = self._without_cookies
                            if not is_default_theme:
                                return_url += '&theme=' + theme
                            if not is_default_language:
                                return_url += '&language=' + language
                            if not is_default_choice:
                                return_url += '&wc=' + str(int(without_cookies))

                        g.captchaify_page = True
                        return redirect(return_url)

                    if is_failed_captcha:
                        self._add_failed_captcha_attempt(client_ip)

                    return self._display_captcha(
                        is_error = is_failed_captcha, return_path = quote(return_path)
                    )
                except Exception as exc:
                    handle_exception(exc)

                    g.captchaify_page = True
                    return redirect(self._create_route_url('blocked'))

            if self.allow_customization:
                @app.route('/change_language-' + route_id)
                def change_language_captchaify() -> Response:
                    """
                    Handle requests for changing the language preference.

                    :return: A Flask response object.
                    """

                    return_path = get_return_path(request)
                    if return_path is None:
                        return_path = '/'

                    change_language_template = self._display_change_language(return_path)
                    if change_language_template:
                        return change_language_template
                    return abort(404)

        elif self.allow_customization:
            app.before_request(self._change_language)

        if self.enable_trueclick:
            @app.route('/trueclick')
            def trueclick_captchaify():
                if request.args.get('js', '1') == '0':
                    return 'Javascript is disabled.'
                return self._correct_template('captcha_trueclick')

        app.before_request(self._rate_limit)
        app.before_request(self._fight_bots)

        app.after_request(self._add_rate_limit)
        app.after_request(self._add_args)
        app.after_request(self._set_cookies)

        if self.crawler_hints:
            app.after_request(self._crawler_hints)

    @property
    def _preferences(self) -> dict:
        """
        This property returns a dictionary of preferences
        based on the current route or endpoint.
        """

        current_url = {
            'captcha_type': self.default_captcha_type,
            'action': self.default_action,
            'rate_limit': self.default_rate_limit,
            'max_rate_limit': self.default_max_rate_limit,
            'template_dir': self.default_template_dir,
        }

        for rule in self.rules:
            rule, preferences = rule['rule'], rule['change']
            if does_match_rule(rule, self.info):
                for preference_name, preference in preferences.items():
                    if preference_name != 'rate_limit':
                        if preference_name == 'captcha_type':
                            if preference.startswith('text'):
                                preference = 'text'
                            elif preference == 'oneclick':
                                preference = 'oneclick_keys'
                            elif preference == 'multiclick':
                                preference = 'multiclick_animals'

                        current_url[preference_name] = preference
                    else:
                        current_url['rate_limit'], current_url['max_rate_limit'] = preference

        routes = []

        if self.as_route:
            routes = ['/blocked-' + self.route_id,
                      '/rate_limited-' + self.route_id,
                      '/captcha-' + self.route_id]
            if self.allow_customization:
                routes.append('/change_language-' + self.route_id)

        if self.enable_trueclick:
            routes.append('/trueclick')

        if request.path in routes:
            current_url['action'] = 'allow'

        if self.dataset_dir is not None:
            current_captcha_motif = current_url['captcha_type'].split('_')[1]
            current_url['dataset_file'] = os.path.join(
                self.dataset_dir, current_captcha_motif + '.json'
            )

        if self.dataset_dir is None or self.default_captcha_type != current_url['captcha_type']:
            current_url['dataset_file'] = DATASET_PATHS.get(
                current_url['captcha_type'], os.path.join(DATASETS_DIR, 'keys.json')
            )

        return current_url


    @property
    def _without_cookies(self) -> Tuple[bool, bool]:
        """
        The cookie Consent of the client
        """

        if self.without_cookies:
            return True, False

        if request.args.get('wc') is not None:
            return request.args.get('wc', '0') == '1', False
        if request.form.get('wc') is not None:
            return request.form.get('wc', '0') == '1', False
        if request.cookies.get('cookieConsent') is not None:
            return request.cookies.get('cookieConsent', '1') == '0', False
        return True, True


    @property
    def ip(self) -> str:
        """
        The IP address of the client
        """

        if hasattr(g, 'client_ip'):
            if isinstance(g.client_ip, str):
                return g.client_ip

        client_ip, is_invalid_ip = get_client_ip(request)

        g.client_ip = client_ip
        g.is_invalid_ip = is_invalid_ip
        return client_ip


    @property
    def invalid_ip(self) -> bool:
        """
        Whether the IP of the client is invalid
        """

        if hasattr(g, 'is_invalid_ip'):
            if isinstance(g.is_invalid_ip, bool):
                return g.is_invalid_ip

        client_ip, is_invalid_ip = get_client_ip(request)

        g.client_ip = client_ip
        g.is_invalid_ip = is_invalid_ip
        return is_invalid_ip


    @property
    def ip_info(self) -> Optional[dict]:
        """
        The information about the Ip address of the client
        """

        ip_info = None
        if hasattr(g, 'client_ip_info'):
            if isinstance(g.client_ip_info, dict):
                return g.client_ip_info
            ip_info = g.client_ip_info

        if ip_info is None:
            if self.invalid_ip:
                ip_info = None
            else:
                ip_info = get_ip_info(self.ip)
                g.client_ip_info = ip_info

        return ip_info


    @property
    def user_agent(self) -> str:
        """
        The User Agent of the client
        """

        if hasattr(g, 'client_user_agent'):
            if isinstance(g.client_user_agent, str):
                return g.client_user_agent

        client_user_agent = request.user_agent.string
        g.client_user_agent = client_user_agent

        return client_user_agent


    @property
    def _client_use_tor(self) -> bool:
        """
        Checks whether the client uses Tor to request the website
        """

        if 'tor' not in self.third_parties or self.invalid_ip:
            return False

        return is_tor_ip(self.ip)


    @property
    def url(self) -> bool:
        """
        Gets the correct client URL
        """

        scheme = request.headers.get('X-Forwarded-Proto', '')
        if scheme not in ['https', 'http']:
            if request.is_secure:
                scheme = 'https'
            else:
                scheme = 'http'

        return scheme + '://' + request.url.split('://')[1]


    @property
    def info(self) -> dict:
        """
        Retrieves and caches client information including
        IP details, geolocation, ISP, and other metadata.

        :return: A dictionary containing client information.
        """

        if hasattr(g, 'client_info'):
            return g.client_info

        url = self.url
        url_info = urlparse(url)

        data = {
            "ip": self.ip, "user_agent": self.user_agent,
            "invalid_ip": self.invalid_ip, "continent": None, "continent_code": None,
            "country": None, "country_code": None, "region": None, "region_code": None,
            "city": None, "district": None, "zip": None, "lat": None, "lon": None,
            "timezone": None, "offset": None, "currency": None, "isp": None, "org": None,
            "as": None, "as_code": None, "reverse": None, "mobile": None, "proxy": None,
            "tor": None, "hosting": None, "forum_spammer": None, "netloc": url_info.netloc,
            "hostname": url_info.hostname, "domain": get_domain_from_url(url),
            "path": url_info.path, "endpoint": request.endpoint,
            "scheme": url_info.scheme, "url": url
        }

        if not self.invalid_ip:
            if 'geoip' in self.third_parties:
                try:
                    with geoip2.database.Reader(GEOLITE_DATA['city']['path']) as reader:
                        city_response = reader.city(self.ip)

                        data.update({
                            "continent": city_response.continent.name,
                            "continent_code": city_response.continent.code,
                            "country": city_response.country.name,
                            "country_code": city_response.country.iso_code,
                            "region": city_response.subdivisions.most_specific.name,
                            "region_code": city_response.subdivisions.most_specific.iso_code,
                            "city": city_response.city.name,
                            "zip": city_response.postal.code,
                            "lat": city_response.location.latitude,
                            "lon": city_response.location.longitude
                        })
                except Exception:
                    pass

                try:
                    with geoip2.database.Reader(GEOLITE_DATA['asn']['path']) as reader:
                        isp_response = reader.asn(self.ip)

                        data.update({
                            "as": isp_response.autonomous_system_organization,
                            "as_code": isp_response.autonomous_system_number,
                        })
                except Exception:
                    pass

            if 'tor' in self.third_parties and not self.invalid_ip:
                is_tor = False
                for client_ip in list(set(get_client_ip(request, True)[0])):
                    try:
                        is_tor = is_tor_ip(client_ip)
                    except Exception as exc:
                        handle_exception(exc)

                    if is_tor:
                        break

                data["tor"] = is_tor

            if 'ipapi' in self.third_parties:
                client_info = self.ip_info

                if client_info is not None:
                    for key, value in client_info.items():
                        if key in ('status', 'query', 'time'):
                            continue

                        if key == 'as' and isinstance(value, str):
                            as_code = value.split(' ')[0].replace('AS', '')
                            if not as_code.isdigit():
                                continue
                            value = int(as_code)

                        new_key = {'region': 'region_code', 'regionname':\
                                   'region', 'as': 'as_code', 'asname': 'as'}\
                            .get(key.lower(), re.sub('([A-Z])', r'_\1', key).lower())
                        if data.get(new_key) is None:
                            if isinstance(value, str) and value.strip() == '':
                                value = None

                            data[new_key] = value

            if 'stopforumspam' in self.third_parties:
                data["forum_spammer"] = is_stopforumspam_spammer(self.ip)

        if data.get('reverse') is None:
            try:
                socket.setdefaulttimeout(1)
                hostname = socket.gethostbyaddr(self.ip)[0]
                data["reverse"] = hostname if hostname != self.ip else None
            except Exception as exc:
                pass

        g.client_info = data

        return data


    def _load_dataset(self, dataset_path: str) -> dict:
        """
        Loads a dataset from the specified path.

        :param dataset_path: The path to the dataset.
        :return: Returns the dataset dict
        """

        if dataset_path in self.loaded_datasets:
            return self.loaded_datasets[dataset_path]

        dataset = JSON.load(dataset_path)

        new_dataset = {}
        if not len(dataset.keys()) == self.max_dataset_keys:
            max_dataset_keys = min(len(dataset.keys()), self.max_dataset_keys)
            for _ in range(max_dataset_keys):
                random_keyword = secrets.choice(list(dataset.keys()))
                while random_keyword in new_dataset:
                    random_keyword = secrets.choice(list(dataset.keys()))
                new_dataset[random_keyword] = dataset[random_keyword]

        dataset = {keyword: images[:self.max_dataset_images]
                   for keyword, images in new_dataset.items()}

        self.loaded_datasets[dataset_path] = dataset
        return dataset


    def _clean_used_captcha_ids(self) -> None:
        """
        Clean up the expired entries from the used_captcha_ids dictionary.
        """

        cleaned_used_captcha_ids = {}
        for hashed_captcha_id, timestamp in self.used_captcha_ids.items():
            if int(time()) - timestamp <= 200:
                cleaned_used_captcha_ids[hashed_captcha_id] = timestamp
        self.used_captcha_ids = cleaned_used_captcha_ids


    def _add_used_captcha_id(self, captcha_id: str) -> None:
        """
        Add a new captcha id to the used_captcha_ids dictionary.

        :param captcha_id: The captcha id to be added.
        """

        self._clean_used_captcha_ids()
        hashed_captcha_id = Hashing().hash(captcha_id)

        used_captcha_ids = self.used_captcha_ids.copy()
        used_captcha_ids[hashed_captcha_id] = int(time())
        self.used_captcha_ids = used_captcha_ids


    def _was_already_used(self, captcha_id: str) -> bool:
        """
        Check if a captcha id has been previously used.

        :param captcha_id: The captcha id to be checked.
        :return: True if the captcha id has been used, False otherwise.
        """

        for hashed_captcha_id in self.used_captcha_ids:
            if Hashing().compare(captcha_id, hashed_captcha_id):
                return True

        return False


    def _set_client_information(self) -> None:
        """
        Sets the client information for certain requests
        """

        try:
            g.captchaify_page = False
            g.captchaify_captcha = None
            g.is_crawler = False

            client_ip, is_invalid_ip = get_client_ip(request)
            client_user_agent = request.user_agent.string

            if client_ip is None or client_user_agent is None:
                if self.as_route:
                    g.captchaify_page = True
                    return redirect(self._create_route_url('blocked'))

                emoji = random.choice(EMOJIS)
                return self._correct_template('block', emoji = emoji)

            g.client_ip = client_ip
            g.is_invalid_ip = is_invalid_ip
            g.client_user_agent = client_user_agent

            self.info
        except Exception as exc:
            handle_exception(exc)
            if self.as_route:
                g.captchaify_page = True
                return redirect(self._create_route_url('blocked'))

            emoji = random.choice(EMOJIS)
            return self._correct_template('block', emoji = emoji)


    def _correct_template(self, template_type: str, **args) -> any:
        """
        Retrieves and renders templates based on the specified template type.

        :param template_type: The type of template to retrieve and render
        :param **args: Additional keyword arguments to be passed to the template renderer
        """

        g.captchaify_page = True

        if not template_type in ALL_TEMPLATE_TYPES[:5]:
            template_type = 'block'

        template_dir = self._preferences['template_dir']

        page_path = None
        file_name = None

        for file_name in os.listdir(template_dir):
            if file_name.startswith(template_type):
                page_path = os.path.join(template_dir, file_name)
                break

        if page_path is None:
            return abort(404)

        page_ext = page_path.split('.')[-1]

        if page_ext == 'html':
            args['allow_customization'] = self.allow_customization

            without_cookies, is_default_choice = self._without_cookies
            args['is_default_choice'] = is_default_choice
            args['without_cookies'] = without_cookies
            args['as_route'] = self.as_route
            return render_template(
                template_dir, file_name, request,
                without_customization = not self.allow_customization,
                **args
            )
        if page_ext == 'json':
            return JSON.load(page_path)
        if page_ext == 'pkl':
            return PICKLE.load(page_path)
        if page_ext in ['txt', 'xml']:
            with open(page_path, 'r', encoding = 'utf-8') as file:
                return file.read()
        return send_file(page_path)


    def _rate_limit(self) -> Optional[str]:
        """
        Checks for rate limits based on IP addresses and overall request counts.
        """

        try:
            rate_limited_ips = PICKLE.load(RATE_LIMIT_PATH)

            preferences = self._preferences

            rate_limit = preferences['rate_limit']
            max_rate_limit = preferences['max_rate_limit']

            request_count = 0
            ip_request_count = 0

            for hashed_ip, ip_timestamps in rate_limited_ips.items():
                count = sum(1 for request_time in ip_timestamps\
                            if int(time()) - int(request_time) <= 60)

                comparison = Hashing().compare(self.ip, hashed_ip)
                if comparison:
                    ip_request_count += count
                request_count += count

            if (ip_request_count >= rate_limit and not rate_limit == 0) or \
                (request_count >= max_rate_limit and not max_rate_limit == 0):
                if self.as_route:
                    if request.path.startswith('/rate_limited-' + self.route_id):
                        return

                    g.captchaify_page = True
                    return redirect(self._create_route_url('rate_limited'))

                emoji = random.choice(TEA_EMOJIS)
                return self._correct_template('rate_limited', emoji = emoji), 429
        except Exception as exc:
            handle_exception(exc)
            if self.as_route:
                g.captchaify_page = True
                return redirect(self._create_route_url('blocked'))

            emoji = random.choice(EMOJIS)
            return self._correct_template('block', emoji = emoji)


    def _display_change_language(self, return_path: Optional[str] = None) -> str:
        """
        Displays an change language Template with languages to choose from.
        """

        try:
            languages = LANGUAGES

            search = None
            if request.args.get('cs') is not None:
                search = request.args.get('cs')
                if search.strip() != '':
                    languages = search_languages(search, LANGUAGES)

            template_dir = self._preferences['template_dir']

            for file_name in os.listdir(template_dir):
                if file_name.startswith('change_language'):
                    return_url = None
                    if return_path is not None:
                        return_url = get_return_url(return_path, request)

                    without_cookies, is_default_choice = self._without_cookies

                    kwargs = {
                        "search": search, "languages": languages,
                        "return_path": return_path, "return_url": return_url,
                        "allow_customization": self.allow_customization,
                        "is_default_choice": is_default_choice,
                        "without_cookies": without_cookies,
                        "as_route": self.as_route
                    }

                    g.captchaify_page = True

                    return render_template(
                        template_dir, file_name, request,
                        without_customization = not self.allow_customization,
                        **kwargs
                    )
        except Exception as exc:
            handle_exception(exc)


    def _change_language(self) -> Optional[str]:
        """
        Change the language of the web application based on the provided query parameters.
        """

        if request.args.get('ccl') == '1':
            return self._display_change_language()


    def _display_captcha(self, is_error: bool = False,
                         return_path: Optional[str] = None) -> Response:
        """
        Display the appropriate captcha challenge based on preferences.

        :param is_error: Flag indicating if there was an error in the previous captcha attempt.
        :param return_path: The path to return to after successful captcha completion.

        :return: A Flask response object.
        """

        url_path = urlparse(self.url).path
        client_ip = self.ip

        preferences = self._preferences
        captcha_type = preferences['captcha_type'].split('_')[0]
        dataset_file = preferences['dataset_file']

        def display_captcha_text_audio() -> str:
            """
            Generate and display a text and/or audio captcha challenge.

            :return: The HTML content of the captcha template rendered with the captcha data.
            """

            captcha_id = generate_random_string(30)

            captcha_token_data = {
                'id': captcha_id, 'type': captcha_type, 'ip': Hashing().hash(client_ip),
                'user_agent': Hashing().hash(self.user_agent),
                'path': Hashing().hash(url_path), 'time': str(int(time()))
            }

            text_captcha = None
            audio_captcha = None

            if 'text' in captcha_type:
                string_length = random.randint(5, 8)
                image_captcha_code = generate_random_string(string_length, with_punctuation=False)

                image_captcha = ImageCaptcha(width=320, height=120, fonts=[
                    os.path.join(ASSETS_DIR, 'Comic_Sans_MS.ttf'),
                    os.path.join(ASSETS_DIR, 'DroidSansMono.ttf'),
                    os.path.join(ASSETS_DIR, 'Helvetica.ttf')
                ])

                captcha_image = image_captcha.generate(image_captcha_code)

                captcha_image_data = b64encode(captcha_image.getvalue()).decode('utf-8')
                text_captcha = 'data:image/png;base64,' + captcha_image_data

                captcha_token_data['text'] = image_captcha_code

                captcha_audio_data = None
            if 'audio' in captcha_type:
                int_length = random.randint(5, 8)

                audio_captcha_code = generate_random_string(
                    int_length, with_punctuation=False, with_letters=False
                )
                audio_captcha = AudioCaptcha()
                captcha_audio = audio_captcha.generate(audio_captcha_code)

                captcha_audio_data = b64encode(captcha_audio).decode('utf-8')
                audio_captcha = 'data:audio/wav;base64,' + captcha_audio_data

                captcha_token_data['audio'] = audio_captcha_code

            captcha_token = self.sses.encrypt(captcha_token_data)
            if captcha_token is None:
                if self.as_route:
                    g.captchaify_page = True
                    return redirect(self._create_route_url('blocked'))

                emoji = random.choice(EMOJIS)
                return self._correct_template('block', emoji = emoji)

            error_message = 'That was not right, try again!' if is_error else None

            return self._correct_template(
                'captcha_text_audio', error_message = error_message, text_captcha = text_captcha, 
                audio_captcha = audio_captcha, captcha_token = captcha_token,
                route_id = self.route_id, return_path = return_path
            )


        def display_captcha_oneclick() -> str:
            """
            Generate and display a one-click image captcha challenge.

            :return: The HTML content of the captcha template
                     rendered with the one-click captcha data.
            """

            captcha_id = generate_random_string(30)

            captcha_token_data = {
                'id': captcha_id, 'type': captcha_type, 'ip': Hashing().hash(client_ip),
                'user_agent': Hashing().hash(self.user_agent),
                'path': Hashing().hash(url_path), 'time': str(int(time()))
            }

            dataset = self._load_dataset(dataset_file)

            keywords = list(dataset.keys())

            keyword = secrets.choice(keywords)
            captcha_token_data['keyword'] = keyword

            images = dataset[keyword]
            original_image = get_random_image(images)

            other_keywords = []
            for _ in range(5):
                random_keyword = secrets.choice(keywords)
                while random_keyword == keyword or random_keyword in other_keywords:
                    random_keyword = secrets.choice(keywords)

                other_keywords.append(random_keyword)

            random_index = secrets.choice(range(0, len(other_keywords) + 1))
            other_keywords.insert(random_index, keyword)

            captcha_token_data['other_keywords'] = other_keywords

            captcha_images = []
            for keyword in other_keywords:
                images = dataset[keyword]

                random_image = get_random_image(images)
                while random_image in captcha_images or random_image == original_image:
                    random_image = get_random_image(images)
                captcha_images.append(random_image)

            original_image = convert_image_to_base64(manipulate_image_bytes(original_image))

            captcha_images = [
                convert_image_to_base64(
                    manipulate_image_bytes(image, is_small = True)
                    ) for image in captcha_images
            ]
            captcha_images = [{'id': str(i), 'src': image_data}
                              for i, image_data in enumerate(captcha_images)]

            captcha_token = self.sses.encrypt(captcha_token_data)
            if captcha_token is None:
                if self.as_route:
                    g.captchaify_page = True
                    return redirect(self._create_route_url('blocked'))

                emoji = random.choice(EMOJIS)
                return self._correct_template('block', emoji = emoji)

            error_message = 'That was not the right one, try again!' if is_error else None

            return self._correct_template(
                'captcha_oneclick', error_message = error_message, route_id = self.route_id,
                original_image = original_image, captcha_images = captcha_images,
                captcha_token = captcha_token, return_path = return_path
            )


        def display_captcha_multiclick() -> str:
            """
            Generate and display a multi-click image captcha challenge.

            :return: The HTML content of the captcha template
                     rendered with the multi-click captcha data.
            """

            captcha_id = generate_random_string(30)

            captcha_token_data = {
                'id': captcha_id, 'type': captcha_type, 'ip': Hashing().hash(client_ip),
                'user_agent': Hashing().hash(self.user_agent),
                'path': Hashing().hash(url_path), 'time': str(int(time()))
            }

            dataset = self._load_dataset(dataset_file)

            keywords = list(dataset.keys())

            keyword = secrets.choice(keywords)
            captcha_token_data['keyword'] = keyword

            images = dataset[keyword]
            original_image = get_random_image(images)

            other_keywords = []
            for _ in range(9):
                is_original_keyword = secrets.choice(range(0, 17)) < 7
                if is_original_keyword:
                    other_keywords.append(keyword)
                else:
                    random_keyword = secrets.choice(keywords)
                    while random_keyword == keyword or random_keyword in other_keywords:
                        random_keyword = secrets.choice(keywords)
                    other_keywords.append(random_keyword)

            if not any(keyword == keyw for keyw in other_keywords):
                random_index = secrets.choice(range(0, len(other_keywords) + 1))
                other_keywords[random_index] = keyword

            captcha_token_data['other_keywords'] = other_keywords

            captcha_images = []
            for keyword in other_keywords:
                images = dataset[keyword]

                random_image = get_random_image(images)
                while random_image in captcha_images or random_image == original_image:
                    random_image = get_random_image(images)
                captcha_images.append(random_image)

            original_image = convert_image_to_base64(manipulate_image_bytes(original_image))

            captcha_images = [
                convert_image_to_base64(
                    manipulate_image_bytes(image, is_small = True)
                    ) for image in captcha_images
            ]
            captcha_images = [{'id': str(i), 'src': image_data}
                              for i, image_data in enumerate(captcha_images)]

            captcha_token = self.sses.encrypt(captcha_token_data)
            if captcha_token is None:
                if self.as_route:
                    g.captchaify_page = True
                    return redirect(self._create_route_url('blocked'))

                emoji = random.choice(EMOJIS)
                return self._correct_template('block', emoji = emoji)

            error_message = 'That was not the right one, try again!' if is_error else None

            return self._correct_template(
                'captcha_multiclick', error_message = error_message, route_id = self.route_id,
                original_image = original_image, captcha_images = captcha_images,
                captcha_token = captcha_token, return_path = return_path
            )


        captcha_display_functions = {
            'text': display_captcha_text_audio,
            'audio': display_captcha_text_audio,
            'text&audio': display_captcha_text_audio,
            'audio&text': display_captcha_text_audio,
            'oneclick': display_captcha_oneclick,
            'multiclick': display_captcha_multiclick,
        }
        captcha_display_function = captcha_display_functions.get(
            captcha_type, display_captcha_oneclick
        )

        return captcha_display_function()


    def _is_ct_valid(self, captcha_token: Optional[str] = None) -> bool:
        """
        Check the validity of the captcha token.
        
        :param captcha_token: The captcha token to validate. Defaults to None.
        :return: True if the captcha token is valid, False otherwise.
        """

        is_failed_captcha = False

        try:
            url_path = urlparse(request.url).path
            client_ip = self.ip

            if request.method.lower() == 'post':
                ct = request.form.get('ct')
            else:
                ct = request.args.get('ct')

            if ct is not None or captcha_token is not None:
                if captcha_token is None:
                    captcha_token = ct

                decrypted_token_data = self.sses.decrypt(captcha_token)
                if decrypted_token_data is not None:

                    captcha_id = decrypted_token_data['id']
                    if not self._was_already_used(captcha_id):
                        token_captcha_type = decrypted_token_data['type']

                        if token_captcha_type in ['oneclick', 'multiclick']:
                            original_keyword = decrypted_token_data['keyword']
                            keywords: list = decrypted_token_data['other_keywords']

                            if token_captcha_type == 'oneclick':
                                if str(keywords.index(original_keyword))\
                                    != str(request.args.get('ci')):
                                    is_failed_captcha = True

                            if token_captcha_type == 'multiclick':
                                original_keyword_indices = []
                                for i, keyword in enumerate(keywords):
                                    if keyword == original_keyword:
                                        original_keyword_indices.append(i)

                                request_indices = []
                                if request.method.lower() == 'post':
                                    data = request.form
                                else:
                                    data = request.args

                                for key, value in data.items():
                                    if (
                                        value.lower() == '1' and
                                        key.startswith('ci') and
                                        len(key) == 3
                                    ):
                                        index = int(key[-1])
                                        request_indices.append(index)

                                if original_keyword_indices != request_indices:
                                    is_failed_captcha = True
                        else:
                            if request.method.lower() == 'post':
                                text_captcha = request.form.get('tc')
                                audio_captcha = request.form.get('ac')
                            else:
                                text_captcha = request.args.get('tc')
                                audio_captcha = request.args.get('ac')

                            if 'text' in token_captcha_type:
                                captcha_token_text = decrypted_token_data['text']

                                if str(text_captcha.lower().replace('0', 'o')) !=\
                                    captcha_token_text.lower().replace('0', 'o'):
                                    is_failed_captcha = True

                            if 'audio' in token_captcha_type:
                                captcha_token_audio = decrypted_token_data['audio']

                                if str(audio_captcha) != str(captcha_token_audio):
                                    is_failed_captcha = True

                        self._add_used_captcha_id(captcha_id)
                        if not is_failed_captcha:
                            comparison_path = Hashing()\
                                .compare(url_path, decrypted_token_data['path'])

                            comparison_ip = Hashing()\
                                .compare(client_ip, decrypted_token_data['ip'])

                            comparison_user_agent = Hashing()\
                                .compare(self.user_agent,
                                        decrypted_token_data['user_agent'])

                            if not comparison_path or \
                                int(time()) - int(decrypted_token_data['time']) > 120 or \
                                    (not comparison_ip and not comparison_user_agent):
                                is_failed_captcha = True
                            else:
                                return True, False
        except Exception as exc:
            handle_exception(exc)

        return False, is_failed_captcha


    def _is_captcha_verifier_valid(self) -> bool:
        """
        Check the validity of the captcha verifier.

        :return: True if the captcha token is valid, False otherwise.
        """

        try:
            client_ip = self.ip

            captcha_string = None
            if request.args.get('captcha') is not None:
                captcha_string = request.args.get('captcha')
            elif request.cookies.get('captcha') is not None:
                captcha_string = request.cookies.get('captcha')

            if captcha_string is None:
                return False

            if len(captcha_string) != 30:
                return False

            captcha_id = captcha_string[:8]

            solved_captchas = PICKLE.load(SOLVED_CAPTCHAS_PATH)

            for hashed_id, ip_data in solved_captchas.items():
                comparison = Hashing().compare(captcha_id, hashed_id)
                if comparison:
                    crypto = SymmetricCrypto(self.captcha_secret)
                    ip = crypto.decrypt(ip_data['ip'])
                    user_agent = crypto.decrypt(ip_data['user_agent'])

                    if not None in [ip, user_agent]:
                        if not int(time()) - int(ip_data['time']) > self.verification_age:
                            if ip == client_ip and user_agent == self.user_agent:
                                return True
                    break
        except Exception as exc:
            handle_exception(exc)

        return False


    def _to_many_attempts(self, action: str) -> bool:
        """
        Check if there are too many failed attempts for the specified action.

        :param action: The action for which to check the failed attempts.
        :return: True if there are too many failed attempts, False otherwise.
        """

        try:
            client_ip = self.ip
            failed_captchas = PICKLE.load(FAILED_CAPTCHAS_PATH)

            for hashed_ip, ip_records in failed_captchas.items():
                comparison = Hashing().compare(client_ip, hashed_ip)
                if comparison:
                    records_length = 0
                    for record in ip_records:
                        if not int(time()) - int(record) > 14400:
                            records_length += 1

                    if (action == 'fight') and records_length > 2\
                        or records_length > 3:

                        return True
        except Exception as exc:
            handle_exception(exc)

        return False


    def _add_failed_captcha_attempt(self, client_ip: str) -> None:
        """
        Add a failed captcha attempt for the specified client IP.

        :param client_ip: The IP address of the client
                          for which to add the failed attempt.
        """

        try:
            failed_captchas = PICKLE.load(FAILED_CAPTCHAS_PATH)

            is_found = False

            for hashed_ip, ip_records in failed_captchas.items():
                comparison = Hashing().compare(client_ip, hashed_ip)
                if comparison:
                    is_found = True

                    records_length = 0
                    for record in ip_records:
                        if not int(time()) - int(record) > 7200:
                            records_length += 1
                    records_length += 1

                    ip_records.append(int(time()))
                    failed_captchas[hashed_ip] = ip_records

                    PICKLE.dump(failed_captchas, FAILED_CAPTCHAS_PATH)

            if not is_found:
                hashed_client_ip = Hashing().hash(client_ip)
                failed_captchas[hashed_client_ip] = [int(time())]

                PICKLE.dump(failed_captchas, FAILED_CAPTCHAS_PATH)
        except Exception as exc:
            handle_exception(exc)


    def _valid_captcha(self, return_path: Optional[str] = None):
        """
        Generates a token to verify that the captcha has been completed.

        :return: None or redirect to a url + args
        """

        client_ip = self.ip

        captcha_id = generate_random_string(8, with_punctuation=False)
        captcha_token = generate_random_string(22, with_punctuation=False)

        solved_captchas = PICKLE.load(SOLVED_CAPTCHAS_PATH)

        while any(Hashing().compare(captcha_id, hashed_id)\
                    for hashed_id, _ in solved_captchas.items()):
            captcha_id = generate_random_string(8, with_punctuation=False)

        symcrypto = SymmetricCrypto(self.captcha_secret)

        data = {
            'time': int(time()),
            'ip': symcrypto.encrypt(client_ip),
            'user_agent': symcrypto.encrypt(self.user_agent),
        }

        solved_captchas = PICKLE.load(SOLVED_CAPTCHAS_PATH)

        solved_captchas[Hashing().hash(captcha_id)] = data

        PICKLE.dump(solved_captchas, SOLVED_CAPTCHAS_PATH)

        g.captchaify_captcha = captcha_id + captcha_token

        if self.as_route:
            url = get_return_url(return_path, request)
        else:
            url = self.url
            url = remove_args_from_url(url)

        char = '&'
        if '?' not in url:
            char = '?'

        if self._without_cookies[0]:
            url += char + 'captcha=' + quote(str(captcha_id + captcha_token))

        if not self.without_other_args:
            theme, is_default_theme = WebPage.client_theme(request)
            language, is_default_language = WebPage.client_language(request)
            without_cookies, is_default_choice = self._without_cookies
            if not is_default_theme:
                url += '&theme=' + theme
            if not is_default_language:
                url += '&language=' + language
            if not is_default_choice:
                url += '&wc=' + str(int(without_cookies))

        g.captchaify_page = True
        return redirect(url)


    def _create_route_url(self, template: str) -> str:
        """
        Creates a route URL with the specified template, including return path,
        theme, and language parameters.

        :param template: The template to be used in constructing the URL.
        :return: The constructed route URL.
        """

        return_path = get_return_path(request)
        if return_path is None:
            return_path = quote(
                extract_path_and_args(
                    rearrange_url(self.url, ['theme', 'language', 'captcha', 'return_path', 'wc'])
                )
            )

        redirect_url = f'/{template}-' + self.route_id + '?return_path=' + return_path

        theme, is_default_theme = WebPage.client_theme(request)
        language, is_default_language = WebPage.client_language(request)
        without_cookies, is_default_choice = self._without_cookies
        if not is_default_theme:
            redirect_url += '&theme=' + theme
        if not is_default_language:
            redirect_url += '&language=' + language
        if not is_default_choice and without_cookies:
            redirect_url += '&wc=' + str(int(without_cookies))

        return redirect_url


    def _fight_bots(self):
        """
        This method checks whether the client is a bot and combats it.
        
        It checks various criteria, including client information, 
            IP reputation, and captcha verification, to determine whether to block,
            show a captcha, or take other actions.
        """

        try:
            client_ip = self.ip

            preferences = self._preferences
            action = preferences['action']

            if action == 'allow':
                return

            is_crawler = crawleruseragents.is_crawler(self.user_agent)

            g.is_crawler = is_crawler

            criteria = [
                self._client_use_tor,
                self.invalid_ip,
                is_crawler and self.block_crawler,
                action == 'fight'
            ]

            if not any(criteria):
                criteria.append(self.info['proxy'])
                criteria.append(self.info['hosting'])
                criteria.append(self.info['forum_spammer'])

            if not any(criteria):
                return

            if action == 'block' or self._to_many_attempts(action):
                if self.as_route:
                    g.captchaify_page = True
                    return redirect(self._create_route_url('blocked'))

                emoji = random.choice(EMOJIS)
                return self._correct_template('block', emoji = emoji)

            is_valid_ct, is_failed_captcha = self._is_ct_valid()
            if is_valid_ct:
                return self._valid_captcha()

            if self._is_captcha_verifier_valid():
                return

            if is_failed_captcha:
                self._add_failed_captcha_attempt(client_ip)

            if self.as_route:
                g.captchaify_page = True
                return redirect(self._create_route_url('captcha'))

            return self._display_captcha(is_error = is_failed_captcha)
        except Exception as exc:
            handle_exception(exc)

            if self.as_route:
                g.captchaify_page = True
                return redirect(self._create_route_url('blocked'))

            emoji = random.choice(EMOJIS)
            return self._correct_template('block', emoji = emoji)


    def _add_rate_limit(self, response: Response) -> Response:
        """
        This method handles rate limiting for incoming requests.

        :param response: The response object to be returned
        """

        try:
            rate_limit = self._preferences['rate_limit']

            if not rate_limit == 0:
                rate_limited_ips = PICKLE.load(RATE_LIMIT_PATH)

                found = False
                for hashed_ip, ip_timestamps in rate_limited_ips.items():
                    comparison = Hashing().compare(self.ip, hashed_ip)
                    if comparison:
                        found = True

                        new_timestamps = []
                        for request_time in ip_timestamps:
                            if not int(time()) - int(request_time) > 60:
                                new_timestamps.append(request_time)
                        new_timestamps = [str(int(time()))] + new_timestamps

                        rate_limited_ips[hashed_ip] = new_timestamps[:round(rate_limit*1.2)]
                        break

                if not found:
                    hashed_client_ip = Hashing().hash(self.ip, 16)
                    rate_limited_ips[hashed_client_ip] = [str(int(time()))]

                PICKLE.dump(rate_limited_ips, RATE_LIMIT_PATH)

            return response
        except Exception as exc:
            handle_exception(exc)


    def _add_args(self, response: Response) -> Response:
        """
        Modifies HTML content of a response by adding arguments to links and forms.

        :param response: The response object to be returned
        """

        try:
            if not response.content_type.startswith('text/html'):
                return response

            without_cookies, is_default_choice = self._without_cookies

            if not without_cookies and getattr(g, 'captchaify_page', False) is True:
                return response

            kwargs = {}

            if not is_default_choice:
                kwargs['wc'] = str(int(without_cookies))

            is_captcha_set = False
            if hasattr(g, 'captchaify_captcha'):
                if g.captchaify_captcha is not None:
                    kwargs['captcha'] = g.captchaify_captcha
                    is_captcha_set = True

            if request.args.get('captcha') is not None and not is_captcha_set:
                kwargs['captcha'] = request.args.get('captcha')

            if self.allow_customization and without_cookies:
                theme, is_default_theme = WebPage.client_theme(request)
                if not is_default_theme:
                    kwargs['theme'] = theme

                language, is_default_language = WebPage.client_language(request)
                if not is_default_language:
                    kwargs['language'] = language

            response.data = WebPage.add_args(response.data, request, **kwargs)

            return response
        except Exception as exc:
            handle_exception(exc)


    def _set_cookies(self, response: Response) -> Response:
        """
        Set cookies in the response object based on various conditions.

        :param response: The response object to be returned
        """

        try:
            if getattr(g, 'captchaify_page', False) is False:
                if self.without_other_args:
                    response.set_cookie('theme', '', max_age=0)
                    response.set_cookie('language', '', max_age=0)

                return response

            without_cookies, is_default_choice = self._without_cookies
            if without_cookies:
                cookies = request.cookies
                for cookie in cookies:
                    response.set_cookie(cookie, '', max_age=0)

                return response

            kwargs = {}
            if not is_default_choice and request.cookies.get('cookieConsent') != '1':
                kwargs["cookieConsent"] = '1'

            if hasattr(g, 'captchaify_captcha'):
                if isinstance(g.captchaify_captcha, str):
                    kwargs["captcha"] = g.captchaify_captcha

            if self.allow_customization:
                theme, is_default_theme = WebPage.client_theme(request)
                if not is_default_theme:
                    kwargs["theme"] = theme

                language, is_default_language = WebPage.client_language(request)
                if not is_default_language:
                    kwargs["language"] = language

            for key, value in kwargs.items():
                response.set_cookie(
                    key, value, max_age = 93312000, samesite = 'Lax',
                    secure = self.app.config.get('HTTPS'),
                    domain = urlparse(request.url).netloc
                )

            return response
        except Exception as exc:
            handle_exception(exc)


    def _crawler_hints(self, response: Response) -> Response:
        """
        This method processes a web response, extracts information,
        and manages a crawler hints cache.

        :param response: The response object to be returned
        """

        try:
            if not response.content_type == 'text/html; charset=utf-8':
                return response

            path = request.path

            found = None

            copy_crawler_hints = self.crawler_hints_cache.copy()

            for hashed_path, path_data in self.crawler_hints_cache.items():
                comparison = Hashing().compare(path, hashed_path)
                if comparison:
                    data_time = path_data['time']
                    title = SymmetricCrypto(path).decrypt(path_data['title'])

                    if title is not None:
                        if not int(time()) - int(data_time) > 7200:
                            found = hashed_path
                        else:
                            del copy_crawler_hints[hashed_path]
                    break

            symmetric_crypto = SymmetricCrypto(path)
            is_captchaify_page = getattr(g, 'captchaify_page', False)

            if found is None and not is_captchaify_page:
                html = response.data
                soup = BeautifulSoup(html, 'html.parser')

                title_tag = soup.title
                title = title_tag.string if title_tag else None
                og_tags = ''.join([og_tag.prettify()\
                                for og_tag in soup.find_all('meta', attrs={'property': 'og'})])

                hashed_path = Hashing().hash(path)

                copy_crawler_hints[hashed_path] = {
                    'time': int(time()),
                    'title': symmetric_crypto.encrypt(str(title)),
                    'og_tags': symmetric_crypto.encrypt(og_tags)
                }

            if copy_crawler_hints != self.crawler_hints_cache:
                self.crawler_hints_cache = copy_crawler_hints

            if found is not None and is_captchaify_page:
                if g.is_crawler:
                    html = response.data
                    soup = BeautifulSoup(html, 'html.parser')

                    title = symmetric_crypto.decrypt(self.crawler_hints_cache[found]['title'])
                    if title is not None and not title == 'None':
                        soup.title.string = title

                    og_tags = symmetric_crypto.decrypt(self.crawler_hints_cache[found]['og_tags'])
                    if not og_tags is None:
                        for tag in og_tags:
                            og_soup = BeautifulSoup(tag, 'html.parser')
                            soup.head.append(og_soup)

                    response = make_response(response)

            return response
        except Exception as exc:
            handle_exception(exc)
