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
import random
import secrets
from typing import Optional, Final, Union
from time import time
from urllib.parse import urlparse, parse_qs, quote
from base64 import b64encode
from bs4 import BeautifulSoup
from captcha.image import ImageCaptcha
from captcha.audio import AudioCaptcha
from flask import Flask, Response, request, g, abort, send_file, make_response, redirect
from .utils import JSON, Hashing, SymmetricCrypto, SSES, WebPage, get_work_dir, generate_random_string,\
    get_client_ip, get_ip_info, remove_args_from_url, request_tor_ips, is_stopforumspam_spammer,\
    search_languages, get_random_image, manipulate_image_bytes, convert_image_to_base64, render_template


WORK_DIR: Final[str] = get_work_dir()
DATA_DIR: Final[str] = os.path.join(WORK_DIR, 'data')
ASSETS_DIR: Final[str] = os.path.join(WORK_DIR, 'assets')
TEMPLATE_DIR: Final[str] = os.path.join(WORK_DIR, 'templates')
DATASETS_DIR: Final[str] = os.path.join(WORK_DIR, 'datasets')

DATASET_PATHS: Final[dict] = {
    'default': os.path.join(DATASETS_DIR, 'oneclick_keys.json'),
    'oneclick_keys': os.path.join(DATASETS_DIR, 'oneclick_keys.json')
}

RATE_LIMIT_PATH: Final[str] = os.path.join(DATA_DIR, 'rate-limits.json')
FAILED_CAPTCHAS_PATH: Final[str] = os.path.join(DATA_DIR, 'failed-captchas.json')
SOLVED_CAPTCHAS_PATH: Final[str] = os.path.join(DATA_DIR, 'solved-captchas.json')

EMOJIS: Final[list] = JSON.load(os.path.join(ASSETS_DIR, 'emojis.json'), [])
TEA_EMOJIS: Final[list] = JSON.load(os.path.join(ASSETS_DIR, 'tea_emojis.json'), [])
LANGUAGES: Final[list] = JSON.load(os.path.join(ASSETS_DIR, 'languages.json'), [])
LANGUAGE_CODES: Final[list] = [language['code'] for language in LANGUAGES]

CRAWLER_USER_AGENTS: Final[list] = [
    'Googlebot', 'bingbot', 'Yahoo! Slurp', 'YandexBot', 'Baiduspider',
    'DuckDuckGo-Favicons-Bot', 'AhrefsBot', 'SemrushBot', 'MJ12bot', 'BLEXBot',
    'SeznamBot', 'Exabot', 'AhrefsBot', 'archive.org_bot', 'Applebot', 'spbot',
    'Genieo', 'linkdexbot', 'Lipperhey Link Explorer', 'SISTRIX Crawler', 'MojeekBot',
    'CCBot', 'Uptimebot', 'XoviBot', 'Neevabot', 'SEOkicks-Robot', 'meanpathbot',
    'MojeekBot', 'RankActiveLinkBot', 'CrawlomaticBot', 'sentibot', 'ExtLinksBot',
    'Superfeedr bot', 'LinkfluenceBot', 'Plerdybot', 'Statbot', 'Brainity', 'Slurp',
    'Barkrowler', 'RanksonicSiteAuditor', 'rogerbot', 'BomboraBot', 'RankActiveLinkBot',
    'mail.ru', 'AI Crawler', 'Xenu Link Sleuth', 'SEMrushBot', 'Baiduspider-render',
    'coccocbot', 'Sogou web spider', 'proximic', 'Yahoo Link Preview', 'Cliqzbot',
    'woobot', 'Barkrowler', 'CodiBot', 'libwww-perl', 'Purebot', 'Statbot', 'iCjobs',
    'Cliqzbot', 'SafeDNSBot', 'AhrefsBot', 'MetaURI API', 'meanpathbot',
    'ADmantX Platform Semantic Analyzer', 'CrawlomaticBot', 'moget', 'meanpathbot',
    'FPT-Aibot', 'Domains Project', 'SimpleCrawler', 'YoudaoBot', 'SafeDNSBot', 'Slurp',
    'XoviBot', 'Baiduspider', 'FPT-Aibot', 'SiteExplorer', 'Lipperhey Link Explorer',
    'CrawlomaticBot', 'SISTRIX Crawler', 'SEMrushBot', 'meanpathbot', 'sentibot',
    'Dataprovider.com', 'BLEXBot', 'YoudaoBot', 'Superfeedr bot', 'moget', 'Genieo',
    'sentibot', 'AI Crawler', 'Xenu Link Sleuth', 'Barkrowler', 'proximic',
    'Yahoo Link Preview', 'Cliqzbot', 'woobot', 'Barkrowler'
]
ALL_CAPTCHA_TYPES: Final[list] = ['text', 'oneclick_keys'] # + emojis, animals
DATASET_SIZES: Final[dict] = {
    'largest': (200, 140),
    'large': (20, 140),
    'medium': (100, 100),
    'normal': (20, 100),
    'small': (20, 36),
    'smaller': (20, 8),
    'little': (6, 8)
}
ALL_ACTIONS: Final[list] = ['let', 'block', 'fight', 'captcha']
ALL_THIRD_PARTIES: Final[list] = ['tor', 'ipapi', 'stopforumspam']
ALL_TEMPLATE_TYPES: Final[list] = [
    'captcha_text', 'captcha_multiclick', 'captcha_oneclick',
    'block', 'rate_limited', 'change_language'
]
ALL_THEMES: Final[list] = ['dark', 'light']
CAPTCHA_TOKEN_KEYS: Final[list] = ['hardness', 'ip', 'user_agent',
                                   'path', 'time', 'text', 'audio']
CAPTCHA_TOKEN_KEYS_ONECLICK: Final[list] = [
    'id', 'hardness', 'ip', 'user_agent',
    'path', 'time', 'keyword', 'other_keywords'
]

if not os.path.isdir(DATA_DIR):
    os.mkdir(DATA_DIR)


class Captchaify:
    """
    Shows the user/bot a captcha before the request first if the request comes from a dangerous IP
    Further function are: Rate Limits, Crawler Hints, Custom Templates, Rules for Specific Routes
    """

    def __init__ (
        self, app: Flask, captcha_types: Optional[dict] = None,
        dataset_size: Union[tuple[int], str] = 'normal', dataset_dir: Optional[str] = None,
        actions: Optional[dict] = None, hardness: Optional[dict] = None,
        rate_limits: Optional[dict] = None, template_dirs: Optional[dict] = None,
        default_captcha_type: str = 'oneclick', default_action: str = 'captcha',
        default_hardness: int = 2, default_rate_limit: Optional[int] = 120,
        default_max_rate_limit = 1200, default_template_dir: Optional[str] = None,
        verification_age: int = 3600, without_cookies: bool = False,
        block_crawler: bool = True, crawler_hints: bool = True,
        third_parties: Optional[list] = None) -> None:
        """
        Configures security settings for a Flask app.

        :param app: Your Flask App.
        :param captcha_types: Dict with which type of captcha should be used.
            	              Example: {"urlpath": "oneclick", "endpoint": "default"}
        :param dataset_size: Tuple containing the number of images of each keyword and the
                             number of keywords or a string with predefined sizes.
        :param actions: Dict with actions for different routes.
                        Example: {"urlpath": "fight", "endpoint": "block"}. Default is None.
        :param hardness: Dict with hardness for different routes.
                         Example: {"urlpath": 1, "endpoint": 2}. Default is None.
        :param rate_limits: Dict with rate limit and max rate limit for different routes.
                            Default is None.
        :param template_dirs: Dict with template folder for different routes.
                              Default is None.
        :param default_captcha_type: Default value of all pages if no special captcha type is given.
        :param default_action: Default value of all pages if no special action is given
                               in actions. Default is "captcha".
        :param default_hardness: Default value of all pages if no special hardness is
                                 given in hardness. Default is 2.
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
        """

        if app is None:
            app = Flask(__name__)

        if isinstance(dataset_size, str):
            self.max_dataset_images, self.max_dataset_keys = DATASET_SIZES.get(dataset_size, (20, 100))
        elif isinstance(dataset_size, tuple):
            self.max_dataset_images, self.max_dataset_keys = dataset_size
        else:
            self.max_dataset_images = 20
            self.max_dataset_keys = 100

        self.app = app

        self.captcha_types = captcha_types if isinstance(captcha_types, dict) else {}
        self.dataset_dir = dataset_dir if isinstance(dataset_dir, str) else None
        self.actions = actions if isinstance(actions, dict) else {}
        self.hardness = hardness if isinstance(hardness, dict) else {}
        self.rate_limits = rate_limits if isinstance(rate_limits, dict) else {}
        self.template_dirs = template_dirs if isinstance(template_dirs, dict) else {}

        if default_captcha_type == 'oneclick':
            default_captcha_type = 'oneclick_keys'

        self.default_captcha_type = default_captcha_type if default_captcha_type\
                                    in ALL_CAPTCHA_TYPES else 'default'
        self.default_action = default_action if default_action in ALL_ACTIONS else 'captcha'
        self.default_hardness = default_hardness if default_hardness in [1, 2, 3] else 2
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

        captcha_secret = generate_random_string(32)
        self.captcha_secret = captcha_secret

        self.sses = SSES(SymmetricCrypto(captcha_secret))

        if 'tor' in self.third_parties:
            tor_exit_ips = request_tor_ips()

            if not isinstance(tor_exit_ips, list):
                tor_exit_ips = []
        else:
            tor_exit_ips = []

        self.tor_exit_ips = tor_exit_ips

        if self.crawler_hints:
            self.crawler_hints_cache = {}

        self.used_captcha_ids = {}
        self.loaded_datasets = {}

        app.before_request(self._set_client_information)
        app.before_request(self._change_language)
        app.before_request(self._rate_limit)
        app.before_request(self._fight_bots)

        app.after_request(self._add_rate_limit)
        if self.without_cookies:
            app.after_request(self._add_args)
        else:
            app.after_request(self._set_cookies)

        if self.crawler_hints:
            app.after_request(self._crawler_hints)

    @property
    def _preferences(self) -> dict:
        """
        This property returns a dictionary of preferences based on the current route or endpoint.
        """

        def is_correct_route(path: str):
            """
            Helper function to determine if the provided path matches the current route or endpoint.

            :param path: The path to check against the current route or endpoint
            """

            url_path = urlparse(request.url).path
            url_endpoint = request.endpoint

            url = url_path
            if not '/' in path:
                url = url_endpoint

            if '*' in path:
                real_path = path.replace('*', '')
                if (path.startswith('*') and path.endswith('*') and real_path in url) or \
                    (path.startswith('*') and url.endswith(real_path)) or \
                        (path.endswith('*') and url.startswith(real_path)):
                    return True
                first_part, second_part = path.split('*')[0], path.split('*')[1]

                if url.startswith(first_part) and url.endswith(second_part):
                    return True

            else:
                if path == url_endpoint:
                    return True

            return False

        current_url = {
            'captcha_type': self.default_captcha_type,
            'action': self.default_action,
            'hardness': self.default_hardness,
            'rate_limit': self.default_rate_limit,
            'max_rate_limit': self.default_max_rate_limit,
            'template_dir': self.default_template_dir,
        }

        preferences = {
            'captcha_type': self.captcha_types,
            'action': self.actions,
            'hardness': self.hardness,
            'rate_limit': self.rate_limits,
            'template_dir': self.template_dirs
        }

        for preference_name, preference in preferences.items():
            if len(preference) == 0:
                continue
            for path, path_preference in preference.items():
                if is_correct_route(path):
                    if preference_name != 'rate_limit':
                        if path_preference == 'oneclick':
                            path_preference = 'oneclick_keys'
                        current_url[preference_name] = path_preference
                    else:
                        current_url['rate_limit'], current_url['max_rate_limit'] = path_preference

        if self.dataset_dir is not None:
            current_url['dataset_file'] = os.path.join(self.dataset_dir, current_url['captcha_type'] + '.json')

        if self.dataset_dir is None or self.default_captcha_type != current_url['captcha_type']:
            current_url['dataset_file'] = DATASET_PATHS.get(
                current_url['captcha_type'], os.path.join(DATASETS_DIR, 'oneclick_keys.json')
            )

        return current_url


    @property
    def _client_ip(self) -> str:
        """
        The IP address of the client
        """

        if hasattr(g, 'client_ip'):
            if isinstance(g.client_ip, str):
                return g.client_ip

        client_ip, is_invalid_ip = get_client_ip()

        g.client_ip = client_ip
        g.is_invalid_ip = is_invalid_ip
        return client_ip


    @property
    def _client_invalid_ip(self) -> bool:
        """
        Whether the IP of the client is invalid
        """

        if hasattr(g, 'is_invalid_ip'):
            if isinstance(g.is_invalid_ip, bool):
                return g.is_invalid_ip

        client_ip, is_invalid_ip = get_client_ip()

        g.client_ip = client_ip
        g.is_invalid_ip = is_invalid_ip
        return is_invalid_ip


    @property
    def _client_ip_info(self) -> dict | None:
        """
        The information about the Ip address of the client
        """

        ip_info = None
        if hasattr(g, 'client_ip_info'):
            if isinstance(g.client_ip_info, dict):
                return g.client_ip_info
            else:
                ip_info = g.client_ip_info

        if ip_info is None:
            if self._client_invalid_ip:
                ip_info = None
            else:
                ip_info = get_ip_info(self._client_ip)
                g.client_ip_info = ip_info

        return ip_info


    @property
    def _client_user_agent(self) -> str:
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

        return self._client_ip in self.tor_exit_ips


    @property
    def _client_url(self) -> bool:
        """
        Gets the correct client URL
        """

        scheme = request.headers.get('X-Forwarded-Proto', '')
        if scheme not in ['https', 'http']:
            if request.is_secure:
                scheme = 'https'
            else:
                scheme = 'http'

        return request.url.replace('http', scheme)


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
                while random_keyword in list(new_dataset.keys()):
                    random_keyword = secrets.choice(list(dataset.keys()))
                new_dataset[random_keyword] = dataset[random_keyword]

        dataset = {keyword: images[:self.max_dataset_images] for keyword, images in new_dataset.items()}

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
        self.used_captcha_ids[hashed_captcha_id] = int(time())


    def _check_used_captcha_id(self, captcha_id: str) -> bool:
        """
        Check if a captcha id has been previously used.

        :param captcha_id: The captcha id to be checked.
        :return: True if the captcha id has been used, False otherwise.
        """

        self._clean_used_captcha_ids()
        for hashed_captcha_id, _ in self.used_captcha_ids.items():
            if Hashing().compare(captcha_id, hashed_captcha_id):
                return True
        return False


    def _set_client_information(self) -> None:
        """
        Sets the client information for certain requests
        """

        g.captchaify_page = False
        g.captchaify_captcha = None
        g.is_crawler = False

        client_ip, is_invalid_ip = get_client_ip()
        client_user_agent = request.user_agent.string

        if client_ip is None or client_user_agent is None:
            emoji = random.choice(EMOJIS)
            return self._correct_template('block', emoji = emoji)

        g.client_ip = client_ip
        g.is_invalid_ip = is_invalid_ip
        g.client_user_agent = client_user_agent

        client_ip_info = None
        if 'ipapi' in self.third_parties and not g.is_invalid_ip:
            client_ip_info = get_ip_info(client_ip)

        g.client_ip_info = client_ip_info


    def _correct_template(self, template_type: str, **args) -> any:
        """
        Retrieves and renders templates based on the specified template type.

        :param template_type: The type of template to retrieve and render
        :param **args: Additional keyword arguments to be passed to the template renderer
        """

        if not template_type in ALL_TEMPLATE_TYPES[:5]:
            template_type = 'block'

        template_dir = self._preferences['template_dir']

        page_path = None

        for file_name in os.listdir(template_dir):
            if file_name.startswith(template_type):
                page_path = os.path.join(template_dir, file_name)
                break

        if page_path is None:
            return abort(404)

        page_ext = page_path.split('.')[-1]

        if page_ext == 'html':
            return render_template(template_dir, file_name, request, **args)
        if page_ext == 'json':
            with open(page_path, 'r', encoding = 'utf-8') as file:
                return JSON.load(file)
        if page_ext in ['txt', 'xml']:
            with open(page_path, 'r', encoding = 'utf-8') as file:
                return file.read()
        return send_file(page_path)


    def _rate_limit(self) -> Optional[str]:
        """
        Checks for rate limits based on IP addresses and overall request counts.
        """

        rate_limited_ips = JSON.load(RATE_LIMIT_PATH)

        preferences = self._preferences

        rate_limit = preferences['rate_limit']
        max_rate_limit = preferences['max_rate_limit']

        request_count = 0
        ip_request_count = 0

        for hashed_ip, ip_timestamps in rate_limited_ips.items():
            count = sum(1 for request_time in ip_timestamps\
                        if int(time()) - int(request_time) <= 60)

            comparison = Hashing().compare(self._client_ip, hashed_ip)
            if comparison:
                ip_request_count += count
            request_count += count

        if (ip_request_count >= rate_limit and not rate_limit == 0) or \
            (request_count >= max_rate_limit and not max_rate_limit == 0):
            emoji = random.choice(TEA_EMOJIS)
            return self._correct_template('rate_limited', emoji = emoji), 418


    def _change_language(self) -> Optional[str]:
        """
        Change the language of the web application based on the provided query parameters.
        """

        if request.args.get('ccl') == '1':
            languages = LANGUAGES

            search = None
            if request.args.get('cs') is not None:
                search = request.args.get('cs')
                if search.strip() != '':
                    languages = search_languages(search, LANGUAGES)

            template_dir = self._preferences['template_dir']

            for file_name in os.listdir(template_dir):
                if file_name.startswith('change_language'):
                    return render_template(template_dir, file_name, request,
                                           search = search, languages = languages)


    def _fight_bots(self):
        """
        This method checks whether the client is a bot and combats it.
        
        It checks various criteria, including client information, 
            IP reputation, and captcha verification, to determine whether to block,
            show a captcha, or take other actions.
        """

        url_path = urlparse(request.url).path
        client_ip = self._client_ip

        preferences = self._preferences
        captcha_type = preferences['captcha_type']
        dataset_file = preferences['dataset_file']
        action = preferences['action']
        hardness = preferences['hardness']


        def add_failed_captcha() -> None:
            """
            This function manages the records of failed captcha attempts,
            updating the records based on the client's IP. It checks
            existing records and adds new ones as necessary.
            """

            failed_captchas = JSON.load(FAILED_CAPTCHAS_PATH)

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

                    JSON.dump(failed_captchas, FAILED_CAPTCHAS_PATH)

            if not is_found:
                hashed_client_ip = Hashing().hash(client_ip)
                failed_captchas[hashed_client_ip] = [int(time())]

                JSON.dump(failed_captchas, FAILED_CAPTCHAS_PATH)


        def display_captcha_text(error: bool = False) -> str:
            """
            This function generates and displays text captchas of varying hardness levels.
            It includes text captchas and, optionally, audio captchas.
            The generated captchas are encoded and included in the response
            along with additional information.

            :param error: Indicates whether there was an error in the previous captcha attempt.
            """

            captcha_token_data = {
                'hardness': str(hardness), 'ip': Hashing().hash(client_ip),
                'user_agent': Hashing().hash(self._client_user_agent),
                'path': Hashing().hash(url_path), 'time': str(int(time()))
            }

            string_length = (5 if hardness == 1 else 8 if hardness == 2 else 9)\
                            + random.choice([1, 1, 2, 3])

            image_captcha_code = generate_random_string(string_length, with_punctuation=False)

            image_captcha = ImageCaptcha(width=320, height=120, fonts=[
                os.path.join(ASSETS_DIR, 'Comic_Sans_MS.ttf'),
                os.path.join(ASSETS_DIR, 'DroidSansMono.ttf'),
                os.path.join(ASSETS_DIR, 'Helvetica.ttf')
            ])

            captcha_image = image_captcha.generate(image_captcha_code)

            captcha_image_data = b64encode(captcha_image.getvalue()).decode('utf-8')
            captcha_image_data = 'data:image/png;base64,' + captcha_image_data

            captcha_token_data['text'] = image_captcha_code

            captcha_audio_data = None

            if hardness == 3:
                int_length = 8 + random.choice([1, 2, 3, 4, 5, 6])

                audio_captcha_code = generate_random_string(int_length, with_punctuation=False,
                                                            with_letters=False)
                audio_captcha = AudioCaptcha()
                captcha_audio = audio_captcha.generate(audio_captcha_code)

                captcha_audio_data = b64encode(captcha_audio).decode('utf-8')
                captcha_audio_data = 'data:audio/wav;base64,' + captcha_audio_data

                captcha_token_data['audio'] = audio_captcha_code

            captcha_token = self.sses.encrypt(captcha_token_data)

            error = 'That was not right, try again!' if error else None

            return self._correct_template(
                'captcha_text', error = error, text_captcha = captcha_image_data, 
                audio_captcha = captcha_audio_data, captcha_token = captcha_token
            )


        def display_captcha_oneclick(error: bool = False) -> str:
            captcha_id = generate_random_string(30)

            captcha_token_data = {
                'id': captcha_id,
                'hardness': str(hardness), 'ip': Hashing().hash(client_ip),
                'user_agent': Hashing().hash(self._client_user_agent),
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

            random_index = secrets.choice([0, 1, 2, 3, 4])
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

            captcha_images = [convert_image_to_base64(manipulate_image_bytes(image, is_small = True)) for image in captcha_images]
            captcha_images = [{'id': str(i), 'src': image_data} for i, image_data in enumerate(captcha_images)]

            captcha_token = self.sses.encrypt(captcha_token_data)

            error = 'That was not the right one, try again!' if error else None

            return self._correct_template(
                'captcha_oneclick', error = error, original_image = original_image, 
                captcha_images = captcha_images, captcha_token = captcha_token
            )


        captcha_display_functions = {
            'text': display_captcha_text,
            'oneclick_keys': display_captcha_oneclick
        }
        captcha_display_function = captcha_display_functions.get(captcha_type, display_captcha_oneclick)


        def valid_captcha(hardness: str):
            """
            Generates a token to verify that the captcha has been completed.

            :return: None or redirect to a url + args
            """

            captcha_id = generate_random_string(6, with_punctuation=False)
            captcha_token = generate_random_string(16)

            solved_captchas = JSON.load(SOLVED_CAPTCHAS_PATH)

            while any(Hashing().compare(captcha_id, hashed_id)\
                      for hashed_id, _ in solved_captchas.items()):
                captcha_id = generate_random_string(6, with_punctuation=False)

            symcrypto = SymmetricCrypto(self.captcha_secret)

            data = {
                'time': int(time()),
                'ip': symcrypto.encrypt(client_ip),
                'user_agent': symcrypto.encrypt(self._client_user_agent),
                'hardness': symcrypto.encrypt(str(hardness))
            }

            solved_captchas = JSON.load(SOLVED_CAPTCHAS_PATH)

            solved_captchas[Hashing().hash(captcha_id)] = data

            JSON.dump(solved_captchas, SOLVED_CAPTCHAS_PATH)

            g.captchaify_captcha = captcha_id + captcha_token

            url = remove_args_from_url(self._client_url)
            url += '?captcha=' + quote(g.captchaify_captcha)

            theme, is_default_theme = WebPage.client_theme(request)
            if not is_default_theme:
                url += '&theme=' + theme

            language, is_default_language = WebPage.client_language(request)
            if not is_default_language:
                url += '&language=' + language

            return redirect(url)


        if action == 'let':
            return

        is_crawler = False
        for crawlername in CRAWLER_USER_AGENTS:
            if crawlername.lower() in self._client_user_agent.lower():
                is_crawler = True

        g.is_crawler = is_crawler

        criteria = [
            self._client_use_tor,
            self._client_invalid_ip,
            is_crawler and self.block_crawler,
            action == 'fight'
        ]

        if not any(criteria) and 'ipapi' in self.third_parties:
            ip_info = self._client_ip_info

            if not isinstance(ip_info, dict):
                criteria.append(True)
            else:
                if ip_info.get('proxy', False) or ip_info.get('hosting', False):
                    criteria.append(True)

        if not any(criteria) and 'stopforumspam' in self.third_parties:
            if is_stopforumspam_spammer(client_ip):
                criteria.append(True)

        if not any(criteria):
            return

        if action == 'block':
            emoji = random.choice(EMOJIS)
            return self._correct_template('block', emoji = emoji)

        failed_captchas = JSON.load(FAILED_CAPTCHAS_PATH)

        for hashed_ip, ip_records in failed_captchas.items():
            comparison = Hashing().compare(client_ip, hashed_ip)
            if comparison:
                records_length = 0
                for record in ip_records:
                    if not int(time()) - int(record) > 14400:
                        records_length += 1

                if (action == 'fight' or hardness == 3)\
                    and records_length > 2 or records_length > 3:

                    emoji = random.choice(EMOJIS)
                    return self._correct_template('block', emoji = emoji)

        is_failed_captcha = False

        if request.args.get('ct') is not None:
            captcha_token = request.args.get('ct')

            if captcha_type == 'oneclick_keys':
                choosen_image = request.args.get('ci')
                if not None in [choosen_image, captcha_token]:
                    decrypted_token_data = self.sses.decrypt(captcha_token, CAPTCHA_TOKEN_KEYS_ONECLICK)
                    if decrypted_token_data is not None:
                        captcha_token_hardness = decrypted_token_data['hardness']

                        captcha_id = decrypted_token_data['id']
                        if not self._check_used_captcha_id(captcha_id):
                            if captcha_token_hardness.isdigit():
                                captcha_token_hardness = hardness
                            else:
                                captcha_token_hardness = int(captcha_token_hardness)

                            original_keyword = decrypted_token_data['keyword']
                            keywords: list = decrypted_token_data['other_keywords']
                            correct_index = keywords.index(original_keyword)

                            if not hardness < captcha_token_hardness:
                                comparison_path = Hashing()\
                                    .compare(url_path, decrypted_token_data['path'])

                                comparison_ip = Hashing()\
                                    .compare(client_ip, decrypted_token_data['ip'])

                                comparison_user_agent = Hashing()\
                                    .compare(self._client_user_agent,
                                            decrypted_token_data['user_agent'])

                                self._add_used_captcha_id(captcha_id)
                                if not comparison_path or \
                                    int(time()) - int(decrypted_token_data['time']) > 120 or \
                                        (not comparison_ip and not comparison_user_agent) or \
                                            str(choosen_image) != str(correct_index):
                                    is_failed_captcha = True
                                else:
                                    return valid_captcha(captcha_token_hardness)
            else:
                text_captcha = request.args.get('tc')
                audio_captcha = request.args.get('ac')
                if not None in [text_captcha, captcha_token]:
                    decrypted_token_data = self.sses.decrypt(captcha_token, CAPTCHA_TOKEN_KEYS)
                    if decrypted_token_data is not None:
                        captcha_token_hardness = decrypted_token_data['hardness']

                        if captcha_token_hardness.isdigit():
                            captcha_token_hardness = hardness
                        else:
                            captcha_token_hardness = int(captcha_token_hardness)

                        is_failing = False

                        if captcha_token_hardness == 3:
                            captcha_token_audio = decrypted_token_data['audio']

                            if hardness == 3:
                                if audio_captcha is None:
                                    is_failing = True
                                else:
                                    if str(audio_captcha) != str(captcha_token_audio):
                                        is_failing = True
                            else:
                                if audio_captcha is not None:
                                    if str(audio_captcha) == str(captcha_token_audio):
                                        captcha_token_hardness = hardness
                                else:
                                    captcha_token_hardness = hardness

                        if not is_failing:
                            if not hardness < captcha_token_hardness:
                                comparison_path = Hashing()\
                                    .compare(url_path, decrypted_token_data['path'])

                                comparison_ip = Hashing()\
                                    .compare(client_ip, decrypted_token_data['ip'])

                                comparison_user_agent = Hashing()\
                                    .compare(self._client_user_agent,
                                            decrypted_token_data['user_agent'])

                                if not comparison_path or \
                                    int(time()) - int(decrypted_token_data['time']) > 180 or \
                                        (not comparison_ip and not comparison_user_agent) or \
                                            str(text_captcha.lower()) !=\
                                                str(decrypted_token_data['text'].lower()):
                                    is_failed_captcha = True

                                else:
                                    return valid_captcha(captcha_token_hardness)
                            else:
                                is_failed_captcha = True
                        else:
                            is_failed_captcha = True

        captcha_string = None
        if request.args.get('captcha') is not None:
            captcha_string = request.args.get('captcha')
        elif request.cookies.get('captcha') is not None:
            captcha_string = request.cookies.get('captcha')

        if captcha_string is None:
            if is_failed_captcha:
                add_failed_captcha()
            return captcha_display_function(error=is_failed_captcha)

        if len(captcha_string) != 22:
            if is_failed_captcha:
                add_failed_captcha()
            return captcha_display_function(error=is_failed_captcha)

        captcha_id = captcha_string[:6]

        solved_captchas = JSON.load(SOLVED_CAPTCHAS_PATH)

        for hashed_id, ip_data in solved_captchas.items():
            comparison = Hashing().compare(captcha_id, hashed_id)
            if comparison:
                crypto = SymmetricCrypto(self.captcha_secret)
                ip = crypto.decrypt(ip_data['ip'])
                user_agent = crypto.decrypt(ip_data['user_agent'])
                captcha_hardness = crypto.decrypt(ip_data['hardness'])

                if not None in [ip, user_agent, captcha_hardness]:
                    captcha_hardness = int(captcha_hardness)
                    if not int(time()) - int(ip_data['time']) > self.verification_age\
                        and hardness >= captcha_hardness:

                        if ip == client_ip and user_agent == self._client_user_agent:
                            return
                break

        if is_failed_captcha:
            add_failed_captcha()

        return captcha_display_function(error = is_failed_captcha)


    def _add_rate_limit(self, response: Response) -> Response:
        """
        This method handles rate limiting for incoming requests.

        :param response: The response object to be returned
        """

        rate_limit = self._preferences['rate_limit']

        if not rate_limit == 0:
            rate_limited_ips = JSON.load(RATE_LIMIT_PATH)

            found = False
            for hashed_ip, ip_timestamps in rate_limited_ips.items():
                comparison = Hashing().compare(self._client_ip, hashed_ip)
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
                hashed_client_ip = Hashing().hash(self._client_ip, 16)
                rate_limited_ips[hashed_client_ip] = [str(int(time()))]

            JSON.dump(rate_limited_ips, RATE_LIMIT_PATH)

        return response


    def _set_cookies(self, response: Response) -> Response:
        """
        Set cookies in the response object based on various conditions.

        :param response: The response object to be returned
        """

        response = make_response(response)

        if self.without_cookies:
            return response

        if hasattr(g, 'captchaify_captcha'):
            if g.captchaify_captcha is not None:
                response.set_cookie('captcha', g.captchaify_captcha,
                                    max_age = self.verification_age, httponly = True,
                                    secure = self.app.config.get('HTTPS'))

        theme, is_default_theme = WebPage.client_theme(request)
        if not is_default_theme:
            response.set_cookie('theme', theme, max_age = 93312000,
                                httponly = True, secure = self.app.config.get('HTTPS'))

        language, is_default_language = WebPage.client_language(request)
        if not is_default_language:
            response.set_cookie('language', language,
                                max_age = 93312000, httponly = True,
                                secure = self.app.config.get('HTTPS'))

        return response


    def _add_args(self, response: Response) -> Response:
        """
        Modifies HTML content of a response by adding arguments to links and forms.

        :param response: The response object to be returned
        """

        if not response.content_type == 'text/html; charset=utf-8':
            return response

        args = {}
        is_captcha_set = False
        if hasattr(g, 'captchaify_captcha'):
            if g.captchaify_captcha is not None:
                args['captcha'] = g.captchaify_captcha
                is_captcha_set = True

        if request.args.get('captcha') is not None and not is_captcha_set:
            args['captcha'] = request.args.get('captcha')

        response.data = WebPage.add_args(response.data, request, **args)

        return response


    def _crawler_hints(self, response: Response) -> Response:
        """
        This method processes a web response, extracts information,
        and manages a crawler hints cache.

        :param response: The response object to be returned
        """

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
