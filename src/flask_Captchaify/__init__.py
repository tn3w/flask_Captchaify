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
from typing import Tuple, Optional, Final
from time import time
from urllib.parse import urlparse, parse_qs, quote
from base64 import b64encode
import pkg_resources
from bs4 import BeautifulSoup
from captcha.image import ImageCaptcha
from captcha.audio import AudioCaptcha
from flask import Flask, request, g, abort, send_file, make_response, redirect, Response
from .utils import JSON, generate_random_string, WebPage, get_client_ip, Hashing,\
                   SymmetricCrypto, get_ip_info, remove_args_from_url, request_tor_ips,\
                   is_stopforumspam_spammer, SSES, search_languages


DATA_DIR: Final[str] = pkg_resources.resource_filename('flask_Captchaify', 'data')
ASSETS_DIR: Final[str] = pkg_resources.resource_filename('flask_Captchaify', 'assets')
TEMPLATE_DIR: Final[str] = pkg_resources.resource_filename('flask_Captchaify', 'templates')

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
ALL_CAPTCHA_TYPES: Final[list] = ['default'] # + emojis, animals
ALL_ACTIONS: Final[list] = ['let', 'block', 'fight', 'captcha']
ALL_THIRD_PARTIES: Final[list] = ['tor', 'ipapi', 'stopforumspam']
ALL_TEMPLATE_TYPES: Final[list] = ['captcha', 'captcha_choose',
                                   'block', 'rate_limited', 'change_language']
ALL_THEMES: Final[list] = ['dark', 'light']
CAPTCHA_TOKEN_KEYS: Final[list] = ['hardness', 'ip', 'user_agent',
                                   'path', 'time', 'text', 'audio']

if not os.path.isdir(DATA_DIR):
    os.mkdir(DATA_DIR)


class Captcha:
    """
    Shows the user/bot a captcha before the request first if the request comes from a dangerous IP
    Further function are: Rate Limits, Crawler Hints, Custom Templates, Rules for Specific Routes
    """

    def __init__ (
        self, app: Flask, captcha_types: str = 'default', actions: Optional[dict] = None,
        hardness: Optional[dict] = None, rate_limits: Optional[dict] = None,
        template_dirs: Optional[dict] = None, default_captcha_type: Optional[dict] = None,
        default_action: str = 'captcha', default_hardness: int = 2,
        default_rate_limit: Optional[int] = 120, default_max_rate_limit = 1200,
        default_template_dir: Optional[str] = None, verification_age: int = 3600,
        without_cookies: bool = False, block_crawler: bool = True,
        crawler_hints: bool = True, third_parties: Optional[list] = None) -> None:
        """
        Configures security settings for a Flask app.

        :param app: Your Flask App.
        :param captcha_types: Which type of captcha should be used.
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

        self.app = app

        self.captcha_types = captcha_types if isinstance(captcha_types, dict) else {}
        self.actions = actions if isinstance(actions, dict) else {}
        self.hardness = hardness if isinstance(hardness, dict) else {}
        self.rate_limits = rate_limits if isinstance(rate_limits, dict) else {}
        self.template_dirs = template_dirs if isinstance(template_dirs, dict) else {}

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
            'template_dir': self.default_template_dir
        }

        preferences = [
            {'name': 'captcha_type', 'list': self.captcha_types},
            {'name': 'action', 'list': self.actions},
            {'name': 'hardness', 'list': self.hardness},
            {'name': 'rate_limits', 'list': self.rate_limits},
            {'name': 'template_dir', 'list': self.template_dirs}
        ]

        for preference in preferences:
            if len(preference['list']) == 0:
                continue
            for path, path_preference in preference.items():
                if is_correct_route(path):
                    if preference['name'] != 'rate_limits':
                        current_url[preference['name']] = path_preference
                    else:
                        current_url['rate_limit'], current_url['max_rate_limit'] = path_preference

        return current_url


    @property
    def _client_language(self) -> Tuple[str, bool]:
        """
        Which language the client prefers

        :return language: The client languge
        :return is_default: Is Default Value
        """

        language_from_args = request.args.get('language')
        language_from_cookies = request.cookies.get('language')
        language_from_form = request.form.get('language')

        chosen_language = (
            language_from_args
            if language_from_args in LANGUAGE_CODES
            else (
                language_from_cookies
                if language_from_cookies in LANGUAGE_CODES
                else (
                    language_from_form
                    if language_from_form in LANGUAGE_CODES
                    else None
                )
            )
        )

        if chosen_language is None:
            preferred_language = request.accept_languages.best_match(LANGUAGE_CODES)

            if preferred_language is not None:
                return preferred_language, False
        else:
            return chosen_language, False

        return 'en', True


    @property
    def _client_theme(self) -> Tuple[str, bool]:
        """
        Which color theme the user prefers
        
        :return theme: The client theme
        :return is_default: Is default Value
        """

        theme_from_args = request.args.get('theme')
        theme_from_cookies = request.cookies.get('theme')
        theme_from_form = request.form.get('theme')

        theme = (
            theme_from_args
            if theme_from_args in ALL_THEMES
            else (
                theme_from_cookies
                if theme_from_cookies in ALL_THEMES
                else (
                    theme_from_form
                    if theme_from_form in ALL_THEMES
                    else None
                )
            )
        )

        if theme is None:
            return 'light', True

        return theme, False


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
            theme, is_default_theme = self._client_theme
            return self._correct_template('block', emoji = emoji,
                                          theme = theme, is_default_theme = is_default_theme)

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

        if not template_type in ALL_TEMPLATE_TYPES[:4]:
            template_type = 'block'

        template_dir = self._preferences['template_dir']

        page_path = None

        for file in os.listdir(template_dir):
            if file.startswith(template_type):
                page_path = os.path.join(template_dir, file)
                break

        if page_path is None:
            return abort(404)

        page_ext = page_path.split('.')[-1]

        if page_ext == 'html':
            client_language, _ = self._client_language
            html = WebPage.render_template(page_path, client_language = client_language,  **args)
            return html
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
            theme, is_default_theme = self._client_theme
            return self._correct_template('rate_limited', emoji = emoji,
                                          theme = theme, is_default_theme = is_default_theme), 418


    def _change_language(self) -> Optional[str]:
        """
        Change the language of the web application based on the provided query parameters.
        """

        if request.args.get('captchaify_changelanguage') == '1':
            languages = LANGUAGES

            search = None
            if request.args.get('captchaify_search') is not None:
                search = request.args.get('captchaify_search')
                languages = search_languages(request.args.get('captchaify_search'), LANGUAGES)

            template_dir = self._preferences['template_dir']

            for file in os.listdir(template_dir):
                if file.startswith('change_language'):
                    theme, is_default_theme = self._client_theme
                    client_language, _ = self._client_language
                    return WebPage.render_template(os.path.join(template_dir, file),
                                                   client_language = client_language,
                                                   search = search, languages = languages,
                                                   theme = theme,
                                                   is_default_theme = is_default_theme,
                                                   current_url = request.url)


    def _fight_bots(self):
        """
        This method checks whether the client is a bot and combats it.
        
        It checks various criteria, including client information, 
            IP reputation, and captcha verification, to determine whether to block,
            show a captcha, or take other actions.
        """

        url_path = urlparse(request.url).path
        client_ip = self._client_ip


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

                    ip_records.append(str(int(time())))
                    failed_captchas[hashed_ip] = ip_records

                    JSON.dump(failed_captchas, FAILED_CAPTCHAS_PATH)

            if not is_found:
                hashed_client_ip = Hashing().hash(client_ip)
                failed_captchas[hashed_client_ip] = [str(int(time()))]

                JSON.dump(failed_captchas, FAILED_CAPTCHAS_PATH)


        def show_captcha(error: bool = False) -> str:
            """
            This function generates and displays captchas of varying hardness levels.
            It includes image captchas and, optionally, audio captchas.
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

            theme, is_default_theme = self._client_theme
            return self._correct_template(
                'captcha', error = error, text_captcha = captcha_image_data, 
                audio_captcha = captcha_audio_data, captcha_token = captcha_token,
                theme = theme, is_default_theme = is_default_theme, current_url = request.url
            )


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

            if self.without_cookies:
                url = remove_args_from_url(request.url)
                url += '?captcha=' + quote(g.captchaify_captcha)

                theme, is_default_theme = self._client_theme
                if not is_default_theme:
                    url += '&theme=' + theme

                language, is_default_language = self._client_language
                if not is_default_language:
                    url += '&language=' + language

                return redirect(url)
            return


        preferences = self._preferences
        action = preferences['action']
        hardness = preferences['hardness']

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
            theme, is_default_theme = self._client_theme
            return self._correct_template('block', emoji = emoji,
                                          theme = theme, is_default_theme = is_default_theme)

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
                    theme, is_default_theme = self._client_theme

                    return self._correct_template(
                        'block', emoji = emoji, theme = theme,
                        is_default_theme = is_default_theme
                    )

        is_failed_captcha = False

        if request.args.get('captchasolved', '0') == '1':
            text_captcha = request.args.get('textCaptcha')
            audio_captcha = request.args.get('audioCaptcha')
            captcha_token = request.args.get('captchatoken')

            if not None in [text_captcha, captcha_token]:
                decrypted_captcha_token = self.sses.decrypt(captcha_token, CAPTCHA_TOKEN_KEYS)
                if decrypted_captcha_token is not None:
                    captcha_token_hardness = decrypted_captcha_token['hardness']

                    if captcha_token_hardness.isdigit():
                        captcha_token_hardness = hardness
                    else:
                        captcha_token_hardness = int(captcha_token_hardness)

                    is_failing = False

                    if captcha_token_hardness == 3:
                        captcha_token_audio = decrypted_captcha_token['audio']

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
                                .compare(url_path, decrypted_captcha_token['path'])

                            comparison_ip = Hashing()\
                                .compare(client_ip, decrypted_captcha_token['ip'])

                            comparison_user_agent = Hashing()\
                                .compare(self._client_user_agent,
                                         decrypted_captcha_token['user_agent'])

                            if not comparison_path or \
                                int(time()) - int(decrypted_captcha_token['time']) > 180 or \
                                    (not comparison_ip and not comparison_user_agent) or \
                                        str(text_captcha.lower()) !=\
                                            str(decrypted_captcha_token['text'].lower()):
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
            return show_captcha(error=is_failed_captcha)

        if len(captcha_string) != 22:
            if is_failed_captcha:
                add_failed_captcha()
            return show_captcha(error=is_failed_captcha)

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

        return show_captcha(error = is_failed_captcha)


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

        theme, is_default_theme = self._client_theme
        if not is_default_theme:
            response.set_cookie('theme', theme, max_age = 93312000,
                                httponly = True, secure = self.app.config.get('HTTPS'))

        language, is_default_language = self._client_language
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

        theme, is_default_theme = self._client_theme
        if not is_default_theme:
            args['theme'] = theme

        language, is_default_language = self._client_language
        if not is_default_language:
            args['language'] = language

        html = response.data
        soup = BeautifulSoup(html, 'html.parser')

        def has_argument(url, arg):
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            return arg in query_params

        for anchor in soup.find_all('a'):
            if not 'href' in anchor.attrs:
                continue

            if '://' in anchor['href']:
                anchor_host = urlparse(anchor['href']).netloc
                if not anchor_host == request.host:
                    continue
            elif not anchor['href'].startswith('/') and \
                not anchor['href'].startswith('#') and \
                    not anchor['href'].startswith('?') and \
                        not anchor['href'].startswith('&'):
                continue

            for arg, content in args.items():
                if not has_argument(anchor['href'], arg):
                    special_character = '?' if '?' not in anchor['href'] else '&'
                    anchor['href'] = anchor['href'] + special_character + arg + '=' + quote(content)

        for form in soup.find_all('form'):
            action = form.get('action')
            if action:
                for arg, content in args.items():
                    if not has_argument(action, arg):
                        special_character = '?' if '?' not in action else '&'
                        form['action'] = action + special_character + arg + '=' + quote(content)

            existing_names = set()
            for input_tag in form.find_all('input'):
                existing_names.add(input_tag.get('name'))

            added_input = ''
            for arg, content in args.items():
                if arg not in existing_names:
                    added_input += f'<input type="hidden" name="{arg}" value="{content}">'

            form_button = form.find('button')
            if form_button:
                form_button.insert_before(BeautifulSoup(added_input, 'html.parser'))
            else:
                form.append(BeautifulSoup(added_input, 'html.parser'))

        response.data = soup.prettify()

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
