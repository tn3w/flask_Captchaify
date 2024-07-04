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
import json
import random
import secrets
import urllib.parse
import urllib.request
from time import time
from base64 import b64encode
from urllib.parse import urlparse, quote
from typing import Optional, Final, Union, Tuple, Callable
from markupsafe import Markup
from bs4 import BeautifulSoup
from captcha.image import ImageCaptcha
from captcha.audio import AudioCaptcha
from flask import Flask, Response, request, g, abort, send_file, make_response, redirect, jsonify
from .utils import DATASETS_DIR, DATA_DIR, TEMPLATE_DIR, ASSETS_DIR, JSON, PICKLE, Hashing,\
    SymmetricCrypto, SSES, generate_random_string, remove_all_args_from_url, search_languages,\
    get_random_image, manipulate_image_bytes, convert_image_to_base64, get_return_path,\
    get_return_url, extract_path_and_args, handle_exception, get_domain_from_url,\
    validate_captcha_response, remove_args_from_url, extract_args, get_char
from .webtoolbox import WebToolbox, asset, render_template
from .req_info import RequestInfo, update_geolite_databases, matches_rule, is_valid_ip
from .altcha import Altcha
from .embed import CaptchaEmbed
from .trueclick import TrueClick


RATE_LIMIT_PATH: Final[str] = os.path.join(DATA_DIR, 'rate-limits.pkl')
FAILED_CAPTCHAS_PATH: Final[str] = os.path.join(DATA_DIR, 'failed-captchas.pkl')
SOLVED_CAPTCHAS_PATH: Final[str] = os.path.join(DATA_DIR, 'solved-captchas.pkl')

EMOJIS: Final[list] = JSON.load(os.path.join(ASSETS_DIR, 'emojis.json'), [])
TEA_EMOJIS: Final[list] = JSON.load(os.path.join(ASSETS_DIR, 'tea_emojis.json'), [])
LANGUAGES: Final[list] = JSON.load(os.path.join(ASSETS_DIR, 'languages.json'), [])
LANGUAGE_CODES: Final[list] = [language['code'] for language in LANGUAGES]

ALL_CAPTCHA_TYPES: Final[list] = [
    'text', 'audio', 'text&audio', 'audio&text', 'oneclick',
    'multiclick', 'recaptcha', 'hcaptcha', 'turnstile',
    'friendlycaptcha', 'altcha', 'trueclick'
]
ALL_DATASET_TYPES: Final[list] = ['keys', 'animals', 'ki-dogs']
ALL_ACTIONS: Final[list] = ['allow', 'block', 'fight', 'auto']
ALL_THIRD_PARTIES: Final[list] = ['geoip', 'tor', 'ipapi', 'stopforumspam']
ALL_TEMPLATE_TYPES: Final[list] = [
    'captcha_text_audio', 'captcha_multiclick', 'captcha_oneclick',
    'captcha_third_party', 'change_language', 'blocked', 'nojs',
    'rate_limited', 'exception'
]
ALL_THEMES: Final[list] = ['dark', 'light']

DATASET_SIZES: Final[dict] = {
    'largest': (200, 140),
    'large': (20, 140),
    'medium': (100, 100),
    'normal': (20, 100),
    'small': (20, 36),
    'smaller': (20, 8),
    'little': (6, 8)
}

CAPTCHA_THIRD_PARTIES_API_URLS: Final[dict] = {
    "recaptcha": "https://www.google.com/recaptcha/api/siteverify",
    "hcaptcha": "https://hcaptcha.com/siteverify",
    "turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    "friendlycaptcha": "https://api.friendlycaptcha.com/api/v1/siteverify"
}

ERROR_CODES: Final[dict] = {
    400: {
        "title": "Bad Request",
        "description": "The server could not understand your request due to invalid syntax."
    },
    401: {
        "title": "Unauthorized",
        "description": "You must authenticate yourself to get the requested response."
    },
    403: {
        "title": "Forbidden",
        "description": "You do not have access rights to the content."
    },
    404: {
        "title": "Not Found",
        "description": "The server cannot find the requested resource."
    },
    405: {
        "title": "Method Not Allowed",
        "description":
            "The request method is known by the server but is not supported by the target resource."
    },
    406: {
        "title": "Not Acceptable",
        "description": (
            "The server cannot produce a response matching the list of acceptable values "
            "defined in your request's proactive content negotiation headers."
        )
    },
    408: {
        "title": "Request Timeout",
        "description": (
            "The server did not receive a complete request message from you within the time that "
            "it was prepared to wait."
        )
    },
    409: {
        "title": "Conflict",
        "description": (
            "The request could not be completed due to a conflict with the current state of "
            "the target resource."
        )
    },
    410: {
        "title": "Gone",
        "description":
            "The requested resource is no longer available and will not be available again."
    },
    411: {
        "title": "Length Required",
        "description":
            "The server refuses to accept the request without a defined Content-Length header."
    },
    412: {
        "title": "Precondition Failed",
        "description": (
            "The server does not meet one of the preconditions that you put on "
            "the request header fields."
        )
    },
    413: {
        "title": "Payload Too Large",
        "description": "The request entity is larger than limits defined by the server."
    },
    414: {
        "title": "URI Too Long",
        "description": "The URI requested by you is longer than the server is willing to interpret."
    },
    415: {
        "title": "Unsupported Media Type",
        "description": "The media format of the requested data is not supported by the server."
    },
    416: {
        "title": "Range Not Satisfiable",
        "description":
            "The range specified by the Range header field in your request can't be fulfilled."
    },
    417: {
        "title": "Expectation Failed",
        "description": (
            "The expectation given in your request's Expect header field could not be met by at "
            "least one of the inbound servers."
        )
    },
    418: {
        "title": "I'm a teapot",
        "description": "The web server rejects the attempt to make coffee with a teapot."
    },
    422: {
        "title": "Unprocessable Entity",
        "description":
            "The request was well-formed but was unable to be followed due to semantic errors."
    },
    423: {
        "title": "Locked",
        "description": "The resource that is being accessed is locked."
    },
    424: {
        "title": "Failed Dependency",
        "description": "The request failed due to failure of a previous request."
    },
    428: {
        "title": "Precondition Required",
        "description": "The origin server requires your request to be conditional."
    },
    429: {
        "title": "Too Many Requests",
        "description": "You have sent too many requests in a given amount of time."
    },
    431: {
        "title": "Request Header Fields Too Large",
        "description": (
            "The server is unwilling to process your request because its header "
            "fields are too large."
        )
    },
    451: {
        "title": "Unavailable For Legal Reasons",
        "description":
            "The server is denying access to the resource as a consequence of a legal demand."
    },
    500: {
        "title": "Internal Server Error",
        "description": "The server has encountered a situation it doesn't know how to handle."
    },
    501: {
        "title": "Not Implemented",
        "description": "The request method is not supported by the server and cannot be handled."
    },
    502: {
        "title": "Bad Gateway",
        "description": (
            "The server, while acting as a gateway or proxy, received an invalid response from "
            "the upstream server."
        )
    },
    503: {
        "title": "Service Unavailable",
        "description": "The server is not ready to handle the request."
    },
    504: {
        "title": "Gateway Timeout",
        "description": (
            "The server is acting as a gateway or proxy and did not receive a timely response "
            "from the upstream server."
        )
    },
    505: {
        "title": "HTTP Version Not Supported",
        "description": "The HTTP version used in your request is not supported by the server."
    }
}

DEFAULT_KWARGS: Final[dict] = {
    "action": 'auto', "captcha_type": 'oneclick',
    "dataset": 'keys', "dataset_size": 'full',
    "dataset_dir": DATASETS_DIR, "hardness": 1,
    "verification_age": 3600, "template_dir": TEMPLATE_DIR,
    "without_customisation": False, "without_cookies": False,
    "without_arg_transfer": False, "without_watermark": False,
    "third_parties": ALL_THIRD_PARTIES, "enable_rate_limit": True,
    "rate_limit": (15, 300), "block_crawler": True,
    "crawler_hints": True, "as_route": False,
    "fixed_route_name": '_captchaify', "theme": 'light', "language": 'en',
    "without_trueclick": False, "error_codes": [],
    "recaptcha_site_key": None, "recaptcha_secret": None,
    "hcaptcha_site_key": None, "hcaptcha_secret": None,
    "turnstile_site_key": None, "turnstile_secret": None,
    "friendly_site_key": None, "friendly_secret": None
}


class Captchaify:
    """
    Shows the user/bot a captcha before the request first if the request comes from a dangerous IP
    Further function are: Rate Limits, Crawler Hints, Custom Templates, Rules for Specific Routes
    """


    def __init__(self, app: Optional[Flask] = None, rules: Optional[dict] = None,
                 action: str = 'auto', captcha_type: str = 'oneclick',
                 dataset: str = 'keys', dataset_size: Union[Tuple[int, int], str] = 'full',
                 dataset_dir: str = DATASETS_DIR, hardness: int = 1, verification_age: int = 3600,
                 template_dir: str = TEMPLATE_DIR, without_customisation: bool = False,
                 without_cookies: bool = False, without_arg_transfer: bool = False,
                 without_watermark: bool = False, third_parties: Optional[list[str]] = None,
                 as_route: bool = False, fixed_route_name: str = '_captchaify',
                 enable_rate_limit: bool = True, rate_limit: Tuple[int, int] = (15, 300),
                 block_crawler: bool = True, crawler_hints: bool = True,
                 theme: str = 'light', language: str = 'en',
                 without_trueclick: bool = False, error_codes: Optional[list] = None,
                 recaptcha_site_key: Optional[str] = None, recaptcha_secret: Optional[str] = None,
                 hcaptcha_site_key: Optional[str] = None, hcaptcha_secret: Optional[str] = None,
                 turnstile_site_key: Optional[str] = None, turnstile_secret: Optional[str] = None,
                 friendly_site_key: Optional[str] = None, friendly_secret: Optional[str] = None
                 ) -> None:
        """
        Initialize the Captchaify instance

        :param app: The Flask app
        :param rules: A dictionary of rules for specific routes
        :param action: The default action to perform
        :param captcha_type: The default type of captcha
        :param dataset: The default dataset
        :param dataset_size: The default dataset size
        :param dataset_dir: The default dataset directory
        :param hardness: The default hardness
        :param verification_age: The default verification age
        :param template_dir: The default template directory
        :param without_customisation: Whether to disable customisation
        :param without_cookies: Whether to disable cookies
        :param without_arg_transfer: Whether to disable argument transfer
        :param without_watermark: Whether to disable watermark
        :param third_parties: The default third parties
        :param as_route: Whether to use a route
        :param fixed_route_name: The fixed route name
        :param enable_rate_limit: Whether to enable rate limit
        :param rate_limit: The default rate limit
        :param block_crawler: Whether to block crawlers
        :param crawler_hints: Whether to show crawler hints
        :param theme: The default theme
        :param language: The default language
        :param without_trueclick: Whether to disable TrueClick
        :param error_codes: The default error codes to handle
        :param recaptcha_site_key: The reCAPTCHA site key
        :param recaptcha_secret: The reCAPTCHA secret
        :param hcaptcha_site_key: The hCaptcha site key
        :param hcaptcha_secret: The hCaptcha secret
        :param turnstile_site_key: The Turnstile site key
        :param turnstile_secret: The Turnstile secret
        :param friendly_site_key: The FriendlyCaptcha site key
        :param friendly_secret: The FriendlyCaptcha secret
        """

        captcha_secret_file = os.path.join(DATA_DIR, 'captcha_secret.txt')

        if os.path.exists(captcha_secret_file):
            with open(captcha_secret_file, 'r', encoding = 'utf-8') as file:
                captcha_secret = file.read()
        else:
            captcha_secret = generate_random_string(32)
            with open(captcha_secret_file, 'w', encoding = 'utf-8') as file:
                file.write(captcha_secret)

        self.captcha_secret = captcha_secret
        self.sses = SSES(captcha_secret, with_keys = True)
        self.altcha = Altcha(secrets.token_bytes(32))

        if third_parties is None:
            third_parties = ALL_THIRD_PARTIES

        if not isinstance(error_codes, list):
            error_codes = []

        kwargs = {
            "action": action, "captcha_type": captcha_type, "dataset": dataset,
            "dataset_size": dataset_size, "dataset_dir": dataset_dir,
            "hardness": hardness, "verification_age": verification_age,
            "template_dir": template_dir, "without_customisation": without_customisation,
            "without_cookies": without_cookies, "without_arg_transfer": without_arg_transfer,
            "without_watermark": without_watermark, "third_parties": third_parties,
            "as_route": as_route, "fixed_route_name": fixed_route_name,
            "enable_rate_limit": enable_rate_limit, "rate_limit": rate_limit,
            "block_crawler": block_crawler, "crawler_hints": crawler_hints,
            "theme": theme, "language": language,
            "without_trueclick": without_trueclick, "error_codes": error_codes,
            "recaptcha_site_key": recaptcha_site_key, "recaptcha_secret": recaptcha_secret,
            "hcaptcha_site_key": hcaptcha_site_key, "hcaptcha_secret": hcaptcha_secret,
            "turnstile_site_key": turnstile_site_key, "turnstile_secret": turnstile_secret,
            "friendly_site_key": friendly_site_key, "friendly_secret": friendly_secret
        }
        self.kwargs = kwargs

        self._download_datasets()
        update_geolite_databases('geoip' in kwargs['third_parties'])
        if kwargs['crawler_hints']:
            self.crawler_hints_cache = {}

        self.used_captcha_ids = {}
        self.loaded_datasets = {}

        self.app = app
        self.rules = rules if isinstance(rules, list) else []
        self.route_id = None

        if app is not None:
            self.add_to_app(app, **kwargs)


    def add_to_app(self, app: Flask, **kwargs: dict) -> None:
        """
        Adds the Captchaify class to the Flask app.

        :param app: The Flask app to add the Captchaify class to.
        :param kwargs: The keyword arguments to pass to the Captchaify class.
        """

        self.app = app

        keyword_args = {}
        for key, value in DEFAULT_KWARGS.items():
            if key in kwargs:
                keyword_args[key] = kwargs[key]
                continue

            keyword_args[key] = value

        self.kwargs = keyword_args

        ################
        #### Routes ####
        ################

        if keyword_args['as_route']:
            if keyword_args.get('fixed_route_name') is None:
                route_id = '-' + generate_random_string(6, False)
                self.route_id = route_id
            else:
                self.route_id = keyword_args["fixed_route_name"]

        app.config['CAPTCHAIFY_CONFIG'] = keyword_args
        if keyword_args['as_route']:
            app.route(
                '/blocked' + self.route_id,
                endpoint = 'blocked_captchaify'
            )(lambda: self._render_block(True))

            app.route(
                '/nojs' + self.route_id,
                endpoint = 'nojs_captchaify'
            )(lambda: self._render_nojs(True))

            app.route(
                '/rate_limited' + self.route_id,
                endpoint = 'rate_limited_captchaify'
            )(lambda: self._render_rate_limit(True))

            app.route(
                '/captcha' + self.route_id,
                methods = ['GET', 'POST'],
                endpoint = 'captcha_captchaify'
            )(lambda: self._captchaify(True))

            if not keyword_args['without_customisation']:
                app.route(
                    '/change_language' + self.route_id,
                    endpoint = 'change_language_captchaify'
                )(lambda: self._render_change_language(True))

        elif not keyword_args['without_customisation']:
            app.before_request(self._change_language)

        ################################
        #### before & after_request ####
        ################################

        app.before_request(self._rate_limit)
        app.before_request(self._check_for_bots)

        app.after_request(self._add_rate_limit)
        app.after_request(self._add_args)
        app.after_request(self._set_cookies)

        if keyword_args['crawler_hints']:
            app.after_request(self._crawler_hints)

        ########################
        #### Error handlers ####
        ########################

        error_codes_to_handle = keyword_args['error_codes']
        if len(error_codes_to_handle) != 0:
            codes = []
            for error_code in error_codes_to_handle:
                if isinstance(error_code, dict):
                    codes.append(error_code['code'])
                    continue

                if isinstance(error_code, str) and error_code.isdigit():
                    error_code = int(error_code)

                codes.append(error_code)

            for error_code in codes:
                app.register_error_handler(error_code, self._render_exception)

        ############################
        #### Context Processors ####
        ############################

        @app.context_processor
        def add_third_parties():
            embed = CaptchaEmbed(self.language[0], self.theme, self.altcha)

            embeds = {'altcha': Markup(embed.get_embed('altcha', None))}
            if not self.kwargs['without_trueclick']:
                embeds['trueclick'] = Markup(embed.get_embed('trueclick', None))

            for third_party in ['recaptcha', 'hcaptcha', 'turnstile', 'friendly']:
                if not None in [keyword_args[f'{third_party}_site_key'],
                                keyword_args[f'{third_party}_secret']]:

                    embeds[third_party] = Markup(
                        embed.get_embed(
                            third_party, keyword_args[f'{third_party}_site_key']
                        )
                    )

            return embeds

        ###################
        #### Trueclick ####
        ###################

        if not self.kwargs['without_trueclick']:

            @app.route('/trueclick_captchaify.js', endpoint = 'trueclick_js_captchaify')
            def trueclickjs_captchaify() -> Response:
                """
                Returns the trueclick.js file.
                
                :return: The trueclick.js file.
                """

                return send_file(
                    os.path.join(ASSETS_DIR, 'trueclick-min.js'),
                    mimetype = 'application/javascript', max_age=31536000
                )

            @app.route('/trueclick_captchaify/<action>', methods = ['GET', 'POST'],
                        endpoint = 'trueclick_captchaify')
            def trueclick_captchaify(action = None) -> Response:
                """
                Generates and verifies trueclick captchas.

                :param action: The action to perform.
                :return: The captcha challenge and dataset if
                            the request is valid, otherwise the error.
                """

                invalid_request = jsonify(
                    {
                        'status': 'error',
                        'error': 'Invalid request',
                        'challenge': None,
                        'dataset': None
                    }
                )

                if not action in ['generate', 'verify']\
                    or request.method.lower() != 'post':
                    return invalid_request

                config = self._current_configuration
                dataset_dir, hardness, dataset =\
                    config['dataset_dir'], config['hardness'], config['dataset']

                trueclick = TrueClick(dataset_dir, hardness)
                if action == 'generate':
                    captcha_challenge = trueclick.generate_captcha(dataset)

                    return jsonify(
                        {
                            'status': 'ok',
                            'error': None,
                            'challenge': captcha_challenge,
                            'dataset': dataset
                        }
                    )

                if not request.is_json:
                    return invalid_request

                data = request.get_json()

                captcha_id, captcha_token = data.get('id'), data.get('token')
                selected_indices = [
                    int(digit) for digit in data.get('selected', '')
                    if digit.isdigit()
                ]

                if not captcha_id or not captcha_token or not selected_indices:
                    return invalid_request

                is_verified = trueclick.verify_captcha(
                    captcha_id, captcha_token, selected_indices
                )

                return jsonify(
                    {
                        'status': 'ok' if is_verified else 'error',
                        'error': 'Invalid captcha' if not is_verified else None,
                        'challenge':
                            trueclick.generate_captcha(dataset)\
                                if not is_verified else None,
                        'dataset': dataset if not is_verified else None,
                    }
                )


    def _download_datasets(self) -> None:
        """
        This method downloads the datasets if they haven't already been
        downloaded.
        """

        if not os.path.exists(DATASETS_DIR):
            os.mkdir(DATASETS_DIR)

        for url in [
            'https://github.com/tn3w/Captcha_Datasets/raw/master/keys.json',
            'https://github.com/tn3w/Captcha_Datasets/raw/master/animals.json',
            'https://github.com/tn3w/Captcha_Datasets/raw/master/ai-dogs.json'
            ]:
            file_name = url.rsplit('/', maxsplit=1)[-1]
            if not os.path.exists(os.path.join(DATASETS_DIR, file_name)):
                print('Downloading', file_name)
                urllib.request.urlretrieve(url, os.path.join(DATASETS_DIR, file_name))


    ####################
    #### Properties ####
    ####################


    @property
    def _req_info(self) -> RequestInfo:
        """
        Property that returns the request information for the current request.

        :return: An object containing information about the current request.
        """

        return RequestInfo(
            request, g, LANGUAGE_CODES,
            self.kwargs['third_parties'],
            'captchaify'
        )


    @property
    def _current_configuration(self) -> dict:
        """
        This property returns a dictionary of the current configuration
        based on the current route or endpoint.
        """

        current_configuration = {
            "action": self.kwargs.get('action', 'captcha'),
            "captcha_type": self.kwargs.get('captcha_type', 'oneclick'),
            "dataset": self.kwargs.get('dataset', 'keys'),
            "dataset_dir": self.kwargs.get('dataset_dir', DATASETS_DIR),
            "hardness": self.kwargs.get('hardness', 1),
            "template_dir": self.kwargs.get('template_dir', TEMPLATE_DIR),
            "enable_rate_limit": self.kwargs.get('enable_rate_limit', True),
            "recaptcha_site_key": self.kwargs.get('recaptcha_site_key', None),
            "recaptcha_secret": self.kwargs.get('recaptcha_secret', None),
            "hcaptcha_site_key": self.kwargs.get('hcaptcha_site_key', None),
            "hcaptcha_secret": self.kwargs.get('hcaptcha_secret', None),
            "turnstile_site_key": self.kwargs.get('turnstile_site_key', None),
            "turnstile_secret": self.kwargs.get('turnstile_secret', None),
            "friendly_site_key": self.kwargs.get('friendly_site_key', None),
            "friendly_secret": self.kwargs.get('friendly_secret', None),
        }

        rate_limit = self.kwargs.get('rate_limit', None)
        if not isinstance(rate_limit, tuple) or not current_configuration['enable_rate_limit']:
            rate_limit = (15, 300)

        current_configuration['rate_limit'] = rate_limit[0]
        current_configuration['max_rate_limit'] = rate_limit[1]

        for config in self.rules:
            if not matches_rule(config['rule'], self._req_info):
                continue

            for config_name, config in config['change'].items():
                current_configuration[config_name] = config

        if current_configuration['dataset'] in ['keys', 'animals', 'ai-dogs']:
            current_configuration['dataset_file'] = os.path.join(
                current_configuration['dataset_dir'],
                current_configuration['dataset'] + '.json'
            )
        else:
            current_configuration['dataset'] = None

        return current_configuration


    @property
    def _own_routes(self) -> list:
        """
        Generates and returns a list of custom routes
        specific to the instance based on its properties.
        """

        routes = []

        if self.kwargs['as_route']:
            routes.extend(
                ['/blocked' + self.route_id, '/rate_limited' + self.route_id,
                 '/captcha' + self.route_id, '/nojs' + self.route_id]
            )
            if not self.kwargs['without_customisation']:
                routes.append('/change_language' + self.route_id)

        if not self.kwargs['without_trueclick']:
            routes.append('/trueclick_captchaify.js')
            routes.append('/trueclick_captchaify/verify')
            routes.append('/trueclick_captchaify/generate')

        return routes


    @property
    def url(self) -> str:
        """
        Returns the URL of the current request.
        """

        return self._req_info.get_url()


    @property
    def ip(self) -> Optional[str]:
        """
        Returns the IP address of the current request.
        """

        return self._req_info.get_ip()


    @property
    def user_agent(self) -> str:
        """
        Returns the user agent of the current request.
        """

        return self._req_info.get_user_agent()


    @property
    def theme(self) -> Tuple[bool, str]:
        """
        Returns the theme of the current request.
        """

        return self._req_info.get_theme(
            self.kwargs['without_customisation'], self.kwargs['theme']
        )


    @property
    def language(self) -> Tuple[bool, str]:
        """
        Returns the language of the current request.
        """

        return self._req_info.get_language(
            self.kwargs['without_customisation'], self.kwargs['language']
        )


    @property
    def without_cookies(self) -> Tuple[bool, bool]:
        """
        Returns the cookies of the current request.
        """

        return self._req_info.get_without_cookies(self.kwargs['without_cookies'])


    @property
    def location(self) -> Optional[dict]:
        """
        Returns the location of the current request.
        """

        info = self._req_info.get_ip_info(
            ['continent', 'continent_code', 'country',
             'country_code', 'region', 'region_code',
             'city', 'zip', 'lat', 'lon']
        )

        return info


    def _get_location_value(self, key: str) -> Optional[str]:
        """
        Returns the value of a location key.
        """

        if self.location is None or key not in self.location:
            return None

        return self.location[key]


    @property
    def continent(self) -> Optional[str]:
        """
        Returns the continent of the current request.
        """

        return self._get_location_value('continent')


    @property
    def continent_code(self) -> Optional[str]:
        """
        Returns the continent code of the current request.
        """

        return self._get_location_value('continent_code')


    @property
    def country(self) -> Optional[str]:
        """
        Returns the country of the current request.
        """

        return self._get_location_value('country')


    @property
    def country_code(self) -> Optional[str]:
        """
        Returns the country code of the current request.
        """

        return self._get_location_value('country_code')


    @property
    def region(self) -> Optional[str]:
        """
        Returns the region of the current request.
        """

        return self._get_location_value('region')


    @property
    def region_code(self) -> Optional[str]:
        """
        Returns the region code of the current request.
        """

        return self._get_location_value('region_code')


    @property
    def city(self) -> Optional[str]:
        """
        Returns the city of the current request.
        """

        return self._get_location_value('city')


    @property
    def zip(self) -> Optional[str]:
        """
        Returns the zip code of the current request.
        """

        return self._get_location_value('zip')


    @property
    def lat(self) -> Optional[str]:
        """
        Returns the latitude of the current request.
        """

        return self._get_location_value('lat')


    @property
    def lon(self) -> Optional[str]:
        """
        Returns the longitude of the current request.
        """

        return self._get_location_value('lon')


    @property
    def as_name(self) -> Optional[str]:
        """
        Returns the autonomous system of the current request.
        """

        return self._req_info.get_ip_info(['as'])


    @property
    def as_number(self) -> Optional[str]:
        """
        Returns the autonomous system number of the current request.
        """

        return self._req_info.get_ip_info(['as_number'])


    @property
    def is_valid_ip(self) -> bool:
        """
        Check if the client's IP is valid.
        """

        return is_valid_ip(self.ip)


    @property
    def is_crawler(self) -> bool:
        """
        Check if the client is a crawler.
        """

        return self._req_info.is_crawler()


    @property
    def is_tor(self) -> bool:
        """
        Check if the client's IP is a Tor exit node.
        """

        return self._req_info.is_tor()


    @property
    def is_spammer(self) -> bool:
        """
        Check if the client is a spammer.
        """

        return self._req_info.is_spammer()


    @property
    def is_proxy(self) -> bool:
        """
        Check if the client is a proxy.
        """

        info = self._req_info.get_ip_info(['proxy', 'hosting'])

        return info.get('proxy', False) is True\
            or info.get('hosting', False) is True


    #######################
    #### Captcha Check ####
    #######################


    def is_captcha_valid(self) -> bool:
        """
        Check if the captcha is valid
        """

        return self._is_captcha_verifier_valid()


    def show_captcha(self, return_path: Optional[str] = None) -> bool:
        """
        Show the captcha
        """

        if return_path is None:
            return_path = get_return_path(request, '/')

        if self._to_many_attempts(self._current_configuration['action']):
            return self._render_block()

        is_valid_ct, is_failed_captcha = self._verify_captcha_token()
        if is_valid_ct:
            return self._valid_captcha(return_path)

        if is_failed_captcha and not self.ip is None:
            self._add_failed_captcha_attempt(self.ip)

        return self._render_captcha(is_failed_captcha, quote(return_path))


    def _is_captcha_valid(self, captcha_type: str) -> bool:
        """	
        Check if the captcha is valid

        :param captcha_type: The type of captcha
        :return: True if the captcha is valid, False otherwise
        """

        third_party_name = {
            'recaptcha': 'g-recaptcha', 'turnstile': 'cf-turnstile',
            'hcaptcha': 'h-captcha', 'friendlycaptcha': 'frc-captcha'
        }.get(captcha_type)

        response_or_solution = 'solution'\
            if captcha_type == 'friendlycaptcha' else 'response'

        key = third_party_name + '-' + response_or_solution
        if request.method.lower() == 'post':
            response_data = request.form.get(key)
        else:
            response_data = request.args.get(key)

        if not isinstance(response_data, str):
            return False

        config = self._current_configuration
        secret = {
            "recaptcha": config['recaptcha_secret'],
            "hcaptcha": config['hcaptcha_secret'],
            "turnstile": config['turnstile_secret'],
            "friendlycaptcha": config['friendly_secret']
        }.get(captcha_type, None)

        post_data = {
            'secret': secret,
            response_or_solution: response_data
        }

        api_url = CAPTCHA_THIRD_PARTIES_API_URLS.get(captcha_type)

        post_data_encoded = urllib.parse.urlencode(post_data).encode('utf-8')
        req = urllib.request.Request(api_url, data=post_data_encoded)

        timeout = 3
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                response_data = response.read()
                response_json = json.loads(response_data)

            if not validate_captcha_response(response_json, get_domain_from_url(self.url)):
                return False
        except Exception:
            return False

        return True


    def is_recaptcha_valid(self) -> bool:
        """
        Check if the recaptcha is valid

        :return: True if the recaptcha is valid, False otherwise
        """

        return self._is_captcha_valid('recaptcha')


    def is_hcaptcha_valid(self) -> bool:
        """
        Check if the hcaptcha is valid

        :return: True if the hcaptcha is valid, False otherwise
        """

        return self._is_captcha_valid('hcaptcha')


    def is_turnstile_valid(self) -> bool:
        """
        Check if the turnstile is valid

        :return: True if the turnstile is valid, False otherwise
        """

        return self._is_captcha_valid('turnstile')


    def is_friendly_valid(self) -> bool:
        """
        Check if the friendly is valid

        :return: True if the friendly is valid, False otherwise
        """

        return self._is_captcha_valid('friendlycaptcha')


    def is_altcha_valid(self) -> bool:
        """
        Check if the altcha is valid

        :return: True if the altcha is valid, False otherwise
        """

        if request.method.lower() == 'post':
            response_data = request.form.get('altcha')
        else:
            response_data = request.args.get('altcha')

        if not isinstance(response_data, str):
            return False

        return self.altcha.verify_challenge(response_data)


    def is_trueclick_valid(self) -> bool:
        """
        Check if the trueclick is valid

        :return: True if the trueclick is valid, False otherwise
        """

        config = self._current_configuration
        dataset_dir, hardness = config['dataset_dir'], config['hardness']

        trueclick = TrueClick(dataset_dir, hardness)

        return trueclick.is_trueclick_valid()


    ########################
    #### Render Methods ####
    ########################


    def _render_exception(self, error: Exception) -> Response:
        """
        Renders the exception page.

        :param error: The error to render.
        :return: The rendered exception page.
        """

        g.captchaify_page = True

        title = None
        description = None

        error_code = str(error).split(' ', maxsplit=1)[0]
        if hasattr(error, 'code'):
            error_code = error.code
            if error_code in ERROR_CODES:
                title = ERROR_CODES[error_code]['title']
                description = ERROR_CODES[error_code]['description']

        elif isinstance(error, Exception):
            error_code = type(error).__name__

        if description is None:
            desc = str(error).replace(error_code, '').strip()
            if desc != '':
                description = desc

        exception = {
            'code': error_code,
            'title': title,
            'description': description
        }

        for exception_code in self.kwargs['error_codes']:
            if not isinstance(exception_code, dict):
                continue

            exception_code_info = exception_code.copy()
            if isinstance(exception_code_info['code'], Callable):
                exception_code_info['code'] = exception_code_info['code'].__name__

            if str(exception_code_info['code']) == str(error_code):
                exception_code_info['code'] = exception_code_info['code_override']
                exception.update(exception_code_info)
                break

        if isinstance(exception['code'], str) and exception['code'].isdigit():
            exception['code'] = int(exception['code'])

        exc_code = 200 if exception['code'] not in ERROR_CODES else exception['code']
        return self._render_template('exception', exception = exception), exc_code


    def _render_block(self, without_redirect: bool = False) -> Response:
        """
        Renders the block page.

        :param without_redirect: Flag indicating if the redirect should be skipped.
        :return: The rendered block page.
        """

        g.captchaify_page = True

        if not without_redirect and self.kwargs['as_route']:
            return redirect(self._create_route_url('blocked'))

        return_path = get_return_path(request)
        if not self.kwargs['as_route']:
            return_path = extract_path_and_args(
                remove_args_from_url(
                    self.url, ['return_path', 'ct', 'ci', 'cs', 'tc', 'ac']
                )
            )
        else:
            return_path = get_return_path(request, '/')

        return_url = get_return_url(return_path, request)

        emoji = random.choice(EMOJIS)

        return self._render_template(
            'blocked', emoji = emoji, return_path = return_path,
            return_url = return_url
        ), 403


    def _render_nojs(self, without_redirect: bool = False) -> Response:
        """
        Renders the nojs page.

        :param without_redirect: Flag indicating if the redirect should be skipped.
        :return: The rendered nojs page.
        """

        g.captchaify_page = True

        if not without_redirect and self.kwargs['as_route']:
            return redirect(self._create_route_url('nojs'))

        return_path = get_return_path(request)
        if not self.kwargs['as_route']:
            return_path = extract_path_and_args(
                remove_args_from_url(
                    self.url, ['return_path', 'ct', 'ci', 'cs', 'tc', 'ac']
                )
            )
        else:
            return_path = get_return_path(request, '/')

        return_url = get_return_url(return_path, request)

        return self._render_template(
            'nojs', return_path = return_path,
            return_url = return_url
        ), 403


    def _render_rate_limit(self, without_redirect: bool = False) -> Response:
        """
        Renders the rate limit page.

        :param without_redirect: Flag indicating if the redirect should be skipped.
        :return: The rendered rate limit page.
        """

        g.captchaify_page = True

        if not without_redirect and self.kwargs['as_route']:
            return redirect(self._create_route_url('rate_limited'))

        return_path = get_return_path(request)
        if not self.kwargs['as_route']:
            return_path = extract_path_and_args(
                remove_args_from_url(
                    self.url, ['return_path', 'ct', 'ci', 'cs', 'tc', 'ac']
                )
            )
        else:
            return_path = get_return_path(request, '/')

        return_url = get_return_url(return_path, request)

        emoji = random.choice(TEA_EMOJIS)
        return self._render_template(
            'rate_limited', emoji = emoji, return_path = return_path,
            return_url = return_url
        ), 429


    def _render_change_language(self, without_redirect: bool = False) -> Response:
        """
        Renders the change language page.

        :param without_redirect: Flag indicating if the redirect should be skipped.
        :return: The rendered change language page.
        """

        return_path = get_return_path(request)
        if return_path is None:
            if not self.kwargs['as_route']:
                return_path = extract_path_and_args(remove_args_from_url(self.url, ['cl']))

        if return_path is None:
            return_path = '/'

        return_url = get_return_url(return_path, request)

        if self.kwargs['as_route']:
            if not without_redirect:
                return redirect(self._create_route_url('change_language'))

        languages = LANGUAGES

        search = None
        if request.args.get('cs') is not None:
            search = request.args.get('cs')
            if search.strip() != '':
                languages = search_languages(search, LANGUAGES)

        return_route = None
        if self.kwargs['as_route']:
            return_route = request.args.get('rr')
            if request.method.lower() == 'post':
                return_route = request.form.get('rr')

            if return_route not in ['captcha', 'blocked', 'nojs', 'rate_limited']:
                return_route = 'captcha'

        args = {
            "search": search, "languages": languages,
            "return_path": return_path, "return_url": return_url,
            "return_url_without_lang": remove_args_from_url(return_url, ['language']),
            "as_route": self.kwargs['as_route'], "return_route": return_route
        }

        g.captchaify_page = True

        return self._render_template(
            'change_language', **args
        )


    def _render_captcha_text_audio(
            self, is_error: bool = False,
            return_path: Optional[str] = None) -> Response:
        """
        Renders the captcha text and audio challenge.

        :param is_error: Flag indicating if there was an error in the previous captcha attempt.
        :param return_path: The path to return to after successful captcha completion.
        :return: A Flask response object.
        """

        captcha_data = self._get_captcha_data()

        config = self._current_configuration
        captcha_type = config['captcha_type']
        hardness = max(1, config['hardness'] / 3 + 0.5)

        text_captcha = None
        audio_captcha = None

        if 'text' in captcha_type:
            string_length = round(random.randint(4, 6) * hardness)
            image_captcha_code = generate_random_string(string_length, with_punctuation=False)

            image_captcha = ImageCaptcha(width=320, height=120, fonts=[
                os.path.join(ASSETS_DIR, 'Comic_Sans_MS.ttf'),
                os.path.join(ASSETS_DIR, 'DroidSansMono.ttf'),
                os.path.join(ASSETS_DIR, 'Helvetica.ttf')
            ])

            captcha_image = image_captcha.generate(image_captcha_code)

            captcha_image_data = b64encode(captcha_image.getvalue()).decode('utf-8')
            text_captcha = 'data:image/png;base64,' + captcha_image_data

            captcha_data['text'] = image_captcha_code

        if 'audio' in captcha_type:
            int_length = round(random.randint(4, 6) * hardness)

            audio_captcha_code = generate_random_string(
                int_length, with_punctuation=False, with_letters=False
            )
            audio_captcha = AudioCaptcha()
            captcha_audio = audio_captcha.generate(audio_captcha_code)

            captcha_audio_data = b64encode(captcha_audio).decode('utf-8')
            audio_captcha = 'data:audio/wav;base64,' + captcha_audio_data

            captcha_data['audio'] = audio_captcha_code

        captcha_token = self.sses.encrypt(captcha_data)
        error_message = 'That was not right, try again!' if is_error else None

        return self._render_template(
            'captcha_text_audio', error_message = error_message, text_captcha = text_captcha, 
            audio_captcha = audio_captcha, captcha_token = captcha_token, return_path = return_path
        )


    def _render_captcha_oneclick(
            self, is_error: bool = False,
            return_path: Optional[str] = None) -> Response:
        """
        Renders the captcha one-click challenge.

        :param is_error: Flag indicating if there was an error in the previous captcha attempt.
        :param return_path: The path to return to after successful captcha completion.
        :return: A Flask response object.
        """

        captcha_data = self._get_captcha_data()

        config = self._current_configuration
        dataset_file = config['dataset_file']
        hardness = config['hardness']

        dataset = self._load_dataset(dataset_file)

        keywords = list(dataset.keys())
        if 'smiling dog' in keywords and len(keywords) == 2:
            keyword = 'smiling dog'
        else:
            keyword = secrets.choice(keywords)

        captcha_data['keyword'] = keyword

        images = dataset[keyword]

        original_image = get_random_image(images)

        if len(keywords) == 2:
            second_value = next(key for key in dataset.keys() if key != keyword)
            other_keywords = [second_value for _ in range(5)]
        else:
            other_keywords = []
            for _ in range(5):
                random_keyword = secrets.choice(keywords)
                while random_keyword == keyword:
                    random_keyword = secrets.choice(keywords)

                other_keywords.append(random_keyword)

        random_index = secrets.choice(range(0, len(other_keywords) + 1))
        other_keywords.insert(random_index, keyword)

        captcha_data['other_keywords'] = other_keywords

        captcha_images = []
        for keyword in other_keywords:
            images = dataset[keyword]

            random_image = get_random_image(images)
            while random_image in captcha_images or random_image == original_image:
                random_image = get_random_image(images)
            captcha_images.append(random_image)

        original_image = convert_image_to_base64(
            manipulate_image_bytes(
                original_image, hardness = hardness
            )
        )

        captcha_images = [
            convert_image_to_base64(
                manipulate_image_bytes(
                    image, is_small = True, hardness = hardness
                )
            ) for image in captcha_images
        ]

        captcha_images = [{'id': str(i), 'src': image_data}
                            for i, image_data in enumerate(captcha_images)]

        captcha_token = self.sses.encrypt(captcha_data)
        error_message = 'That was not the right one, try again!' if is_error else None

        return self._render_template(
            'captcha_oneclick', error_message = error_message,
            original_image = original_image, captcha_images = captcha_images,
            captcha_token = captcha_token, return_path = return_path
        )


    def _render_captcha_multiclick(
            self, is_error: bool = False,
            return_path: Optional[str] = None) -> Response:
        """
        Renders the captcha multiclick challenge.

        :param is_error: Flag indicating if there was an error in the previous captcha attempt.
        :param return_path: The path to return to after successful captcha completion.
        :return: A Flask response object.
        """

        captcha_data = self._get_captcha_data()

        config = self._current_configuration
        dataset_file = config['dataset_file']
        hardness = config['hardness']

        dataset = self._load_dataset(dataset_file)

        keywords = list(dataset.keys())
        if 'smiling dog' in keywords and len(keywords) == 2:
            keyword = 'smiling dog'
        else:
            keyword = secrets.choice(keywords)

        captcha_data['keyword'] = keyword

        images = dataset[keyword]
        original_image = get_random_image(images)

        num_originals = secrets.choice([2, 3, 4])
        other_keywords = [keyword] * num_originals

        while len(other_keywords) < 9:
            random_keyword = secrets.choice(keywords)
            if random_keyword != keyword and\
                (random_keyword not in other_keywords or len(keywords) == 2):

                other_keywords.append(random_keyword)

        secrets.SystemRandom().shuffle(other_keywords)

        captcha_data['correct'] = [i for i, k in enumerate(other_keywords) if k == keyword]

        captcha_images = []
        for keyword in other_keywords:
            images = dataset[keyword]

            random_image = get_random_image(images)
            while random_image in captcha_images or random_image == original_image:
                random_image = get_random_image(images)
            captcha_images.append(random_image)

        original_image = convert_image_to_base64(
            manipulate_image_bytes(original_image, hardness = hardness)
        )

        captcha_images = [
            convert_image_to_base64(
                manipulate_image_bytes(
                    image, is_small = True, hardness = hardness
                )
            ) for image in captcha_images
        ]
        captcha_images = [
            {'id': str(i), 'src': image_data}
            for i, image_data in enumerate(captcha_images)
        ]

        captcha_token = self.sses.encrypt(captcha_data)
        error_message = 'That was not the right one, try again!' if is_error else None

        return self._render_template(
            'captcha_multiclick', error_message = error_message,
            original_image = original_image, captcha_images = captcha_images,
            captcha_token = captcha_token, return_path = return_path
        )


    def _render_captcha_third_parties(
            self, is_error: bool = False,
            return_path: Optional[str] = None) -> Response:
        """
        Renders the captcha third parties challenge.

        :param is_error: Flag indicating if there was an error in the previous captcha attempt.
        :param return_path: The path to return to after successful captcha completion.
        :return: A Flask response object.
        """

        if request.args.get('js', '1') == '0':
            return self._render_nojs()

        config = self._current_configuration
        captcha_type = config['captcha_type']
        hardness = config['hardness']

        site_key = None
        altcha_challenge = None
        strings = None
        if captcha_type == 'altcha':
            altcha_challenge = json.dumps(self.altcha.create_challenge(hardness = hardness))
            strings = json.dumps(self.altcha.localized_text(self.language[0]))
        elif not captcha_type == 'trueclick':
            site_key = {
                "recaptcha": config['recaptcha_site_key'],
                "hcaptcha": config['hcaptcha_site_key'],
                "turnstile": config['turnstile_site_key'],
                "friendlycaptcha": config['friendly_site_key']
            }.get(captcha_type, None)

        captcha_data = self._get_captcha_data()
        captcha_token = self.sses.encrypt(captcha_data)
        error_message = 'Something has gone wrong. Try again.' if is_error else None

        return self._render_template(
            'captcha_third_party', error_message = error_message,
            captcha_token = captcha_token, return_path = return_path,
            third_party = captcha_type, site_key = site_key,
            altcha_challenge = altcha_challenge, strings = strings
        )


    def _render_captcha(self, is_error: bool = False,
                       return_path: Optional[str] = None,
                       without_redirect: bool = False) -> Response:
        """
        Renders the captcha challenge.

        :param is_error: Flag indicating if there was an error in the previous captcha attempt.
        :param return_path: The path to return to after successful captcha completion.
        :param without_redirect: Flag indicating if the redirect should be skipped.
        :return: A Flask response object.
        """

        if not without_redirect and self.kwargs['as_route']:
            return redirect(self._create_route_url('captcha'))

        captcha_type = self._current_configuration['captcha_type']

        captcha_display_functions = {
            "text": self._render_captcha_text_audio,
            "audio": self._render_captcha_text_audio,
            "text&audio": self._render_captcha_text_audio,
            "audio&text": self._render_captcha_text_audio,
            "oneclick": self._render_captcha_oneclick,
            "multiclick": self._render_captcha_multiclick,
            "recaptcha": self._render_captcha_third_parties,
            "hcaptcha": self._render_captcha_third_parties,
            "turnstile": self._render_captcha_third_parties,
            "friendlycaptcha": self._render_captcha_third_parties,
            "altcha": self._render_captcha_third_parties,
            "trueclick": self._render_captcha_third_parties
        }
        captcha_display_function = captcha_display_functions.get(
            captcha_type, self._render_captcha_oneclick
        )

        return captcha_display_function(is_error, return_path)


    def _render_template(self, template: str, **args) -> Response:
        """
        Retrieves and renders templates based on the specified template type.

        :param template: The template to retrieve and render
        :param **args: Additional keyword arguments to be passed to the template renderer
        :return: A Flask response object
        """

        g.captchaify_page = True

        if not template in ALL_TEMPLATE_TYPES:
            template = 'blocked'

        template_dir = self._current_configuration['template_dir']

        page_path, file_name = self._find_template(template)
        if page_path is None:
            return abort(404)

        page_ext = page_path.split('.')[-1]

        if page_ext == 'html':
            g.captchaify_template = file_name

            client_theme, is_default_theme = self.theme
            client_language, is_default_language = self.language
            without_cookies, is_default_choice = self.without_cookies

            template_args = {
                "theme": client_theme,
                "without_cookies": without_cookies,
                "is_default_theme": is_default_theme,
                "language": client_language,
                "is_default_language": is_default_language,
                "alternate_languages": LANGUAGE_CODES
                    if not self.kwargs['without_customisation'] else [],
                "is_default_choice": is_default_choice,
                "as_route": self.kwargs['as_route'],
                "route_id": self.route_id,
                "dataset": self._current_configuration['dataset'],
                "without_watermark": self.kwargs['without_watermark'],
                "without_customisation": self.kwargs['without_customisation'],
                "kwargs_without_cookies": self.kwargs['without_cookies'],
                "template": template,
                "is_return_path_set": get_return_path(
                    request, args.get('return_path', '/')).strip() != '/'
            }

            args.update(template_args)

            for asset_name in [
                'colors', 'cookie_banner_css', 'cookie_banner_html',
                'cookie_banner_js', 'footer_css', 'footer_html']:

                args[asset_name] = asset(asset_name, **args)

            if self.kwargs['as_route']:
                args['captcha_url'] = self._create_route_url('captcha')

            current_url = remove_args_from_url(
                self.url,
                ['theme', 'language'] +
                (['wc'] if not without_cookies else [])
            )
            args.update({
                "current_url_with_config": remove_args_from_url(
                    self.url, ['ct', 'ci', 'cs', 'captcha', 'js']
                ),
                "url_args": extract_args(remove_args_from_url(
                    self.url, ['ct', 'ci', 'cs', 'captcha']
                )),
                "url_args_without_rr": extract_args(remove_args_from_url(
                    self.url, ['ct', 'ci', 'cs', 'captcha', 'rr']
                )),
                "url_args_without_lang": extract_args(remove_args_from_url(
                    self.url, ['ct', 'ci', 'cs', 'captcha', 'rr', 'language']
                )),
                "current_url": remove_args_from_url(
                    current_url, ['ct', 'ci', 'cs', 'captcha', 'tc', 'ac']
                ),
                "current_url_without_cl": remove_args_from_url(current_url, ['cl']),
                "current_url_without_wc": remove_args_from_url(self.url, ['wc']),
                "path": request.path,
                "current_path": quote(
                    extract_path_and_args(
                        remove_args_from_url(self.url, ['theme', 'language'])
                    )
                )
            })

            return render_template(
                template_dir, file_name,
                'en', client_language,
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


    ################################
    #### before & after_request ####
    ################################


    def _rate_limit(self) -> Optional[str]:
        """
        Checks for rate limits based on IP addresses and overall request counts.
        """

        try:
            config = self._current_configuration

            if not config['enable_rate_limit'] or (self.kwargs['as_route']
                and request.path == '/rate_limited' + self.route_id):
                return

            client_ip = self.ip
            if client_ip is None:
                client_ip = 'None'

            rate_limited_ips = PICKLE.load(RATE_LIMIT_PATH)
            rate_limit, max_rate_limit = config['rate_limit'], config['max_rate_limit']

            request_count = 0
            ip_request_count = 0

            for ip, ip_timestamps in rate_limited_ips.items():
                count = sum(1 for request_time in ip_timestamps\
                            if int(time()) - int(request_time) <= 10)

                if ip == client_ip:
                    ip_request_count += count
                request_count += count

            if (ip_request_count >= rate_limit and not rate_limit == 0) or \
                (request_count >= max_rate_limit and not max_rate_limit == 0):
                return self._render_rate_limit()

        except Exception as exc:
            handle_exception(exc)

            return self._render_block()


    def _change_language(self) -> Optional[str]:
        """
        Change the language of the web application based on the provided query parameters.
        """

        if request.args.get('cl') == '1':
            return self._render_change_language()


    def _check_for_bots(self):
        """
        Check if the request is from a bot.
        """

        try:
            if request.path in self._own_routes:
                return

            action = self._current_configuration['action']

            if action == 'allow' or\
                self._is_captcha_verifier_valid():
                return

            if action == 'fight' or not self.is_valid_ip:
                return self._captchaify()

            if self.is_crawler or self.is_proxy\
                or self.is_spammer or self.is_tor:
                return self._captchaify()

        except Exception as exc:
            handle_exception(exc)

            return self._captchaify()


    def _add_rate_limit(self, response: Response) -> Response:
        """
        This method handles rate limiting for incoming requests.

        :param response: The response object to be returned
        :return: The response object with rate limit added
        """

        try:
            client_ip = self.ip
            if not self._current_configuration['enable_rate_limit'] or client_ip is None:
                return response

            rate_limit = self._current_configuration['rate_limit']
            rate_limited_ips = PICKLE.load(RATE_LIMIT_PATH)

            found = False
            for ip, ip_timestamps in rate_limited_ips.items():
                if ip == client_ip:
                    found = True

                    new_timestamps = []
                    for request_time in ip_timestamps:
                        if not int(time()) - int(request_time) > 10:
                            new_timestamps.append(request_time)
                    new_timestamps = [str(int(time()))] + new_timestamps

                    rate_limited_ips[ip] = new_timestamps[:round(rate_limit*1.2)]
                    break

            if not found:
                rate_limited_ips[client_ip] = [str(int(time()))]

            PICKLE.dump(rate_limited_ips, RATE_LIMIT_PATH)

            return response
        except Exception as exc:
            handle_exception(exc)


    def _add_args(self, response: Response) -> Response:
        """
        Modifies HTML content of a response by adding arguments to links and forms.

        :param response: The response object to be returned
        :return: The response object with arguments added
        """

        try:
            if not response.content_type.startswith('text/html'):
                return response

            without_cookies, is_default_choice = self.without_cookies
            if not without_cookies and getattr(g, 'captchaify_page', False) is True:
                return response

            args = {}

            if not is_default_choice and request.args.get('captcha') is None:
                args['wc'] = str(int(without_cookies))

            if self.kwargs['as_route'] and not getattr(
                g, 'captchaify_template', ''
                ).startswith('change_language'):

                return_route = request.args.get('rr')
                if request.method.lower() == 'post':
                    return_route = request.form.get('rr')

                if return_route in ['captcha', 'blocked', 'nojs', 'rate_limited']:
                    args['rr'] = return_route

            is_captcha_set = False
            if hasattr(g, 'captchaify_captcha'):
                if g.captchaify_captcha is not None:
                    args['captcha'] = g.captchaify_captcha
                    is_captcha_set = True

            if request.args.get('captcha') is not None and not is_captcha_set:
                args['captcha'] = request.args.get('captcha')

            if not self.kwargs['without_customisation'] and without_cookies:
                theme, is_default_theme = self.theme
                if not is_default_theme:
                    args['theme'] = theme

                language, is_default_language = self.language
                if not is_default_language:
                    args['language'] = language

            response.data = WebToolbox.add_arguments(response.data, self._req_info, **args)
        except Exception as exc:
            handle_exception(exc)

        return response


    def _set_cookies(self, response: Response) -> Response:
        """
        Set cookies in the response object based on various conditions.

        :param response: The response object to be returned
        :return: The response object with cookies set
        """

        try:
            if getattr(g, 'captchaify_page', False) is False:
                return response

            without_cookies, is_default_choice = self.without_cookies
            if without_cookies:
                cookies = list(dict(request.cookies).keys())
                for cookie in cookies:
                    if cookie != 'captcha':
                        response.delete_cookie(cookie)

                return response

            kwargs = {}

            if hasattr(g, 'captchaify_captcha'):
                if isinstance(g.captchaify_captcha, str):
                    kwargs["captcha"] = g.captchaify_captcha

            if not getattr(g, 'captchaify_no_new_cookies', False):
                if not is_default_choice and request.cookies.get('cookieConsent') != '1':
                    kwargs["cookieConsent"] = '1'

                if not self.kwargs['without_customisation'] and not without_cookies:
                    theme, is_default_theme = self.theme
                    if not is_default_theme:
                        kwargs["theme"] = theme

                    language, is_default_language = self.language
                    if not is_default_language:
                        kwargs["language"] = language
            elif self.kwargs['without_arg_transfer']:
                for cookie in ['cookieConsent', 'theme', 'language']:
                    response.delete_cookie(cookie)

            for key, value in kwargs.items():
                response.set_cookie(
                    key, value, max_age = 93312000, samesite = 'Lax',
                    secure = self.app.config.get('HTTPS'),
                    domain = urlparse(request.url).netloc
                )
        except Exception as exc:
            handle_exception(exc)

        return response


    def _crawler_hints(self, response: Response) -> Response:
        """
        Adds crawler hints to the response if the response is an HTML page.

        :param response: The response object to add crawler hints to.
        :return: The response object with crawler hints added if the response is an HTML page.
        """

        try:
            if not response.content_type == 'text/html; charset=utf-8':
                return response

            path = request.path

            copy_crawler_hints = self.crawler_hints_cache.copy()

            found = None
            for hashed_path, path_data in self.crawler_hints_cache.items():
                comparison = Hashing().compare(path, hashed_path)
                if comparison:
                    data_time = path_data['time']
                    title = SymmetricCrypto(path).decrypt(path_data['title'])

                    if title is not None and not int(time()) - int(data_time) > 7200:
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
                og_tags = ''.join(
                    [og_tag.prettify() for og_tag in\
                     soup.find_all('meta', attrs={'property': 'og'})]
                )

                hashed_path = Hashing().hash(path)

                copy_crawler_hints[hashed_path] = {
                    'time': int(time()),
                    'title': symmetric_crypto.encrypt(str(title)),
                    'og_tags': symmetric_crypto.encrypt(og_tags)
                }

            if copy_crawler_hints != self.crawler_hints_cache:
                self.crawler_hints_cache = copy_crawler_hints

            if found is not None and is_captchaify_page:
                if getattr(g, 'is_crawler', False):
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
        except Exception as exc:
            handle_exception(exc)

        return response


    #########################
    #### Other Functions ####
    #########################


    def _captchaify(self, without_redirect: bool = False) -> Response:
        """
        Captchaify the current request.

        :param without_redirect: If True, the captcha page is not redirected.
        :return: A Flask response object.
        """

        try:
            if request.path in self._own_routes and not without_redirect:
                return

            client_ip = self.ip
            action = self._current_configuration['action']

            if action == 'block' or self._to_many_attempts(action):
                return self._render_block()

            is_valid_ct, is_failed_captcha = self._verify_captcha_token()
            return_path = get_return_path(request, '/')
            if is_valid_ct:
                return self._valid_captcha(return_path)

            if self._is_captcha_verifier_valid():
                if not without_redirect:
                    return

                return_url = get_return_url(return_path, request)
                char = get_char(return_url)

                captcha_string = None
                if request.args.get('captcha') is not None:
                    captcha_string = request.args.get('captcha')
                elif request.cookies.get('captcha') is not None:
                    captcha_string = request.cookies.get('captcha')
                elif request.form.get('captcha') is not None:
                    captcha_string = request.form.get('captcha')

                without_cookies, is_default_choice = self.without_cookies
                if without_cookies and captcha_string is not None:
                    return_url += char + 'captcha=' + captcha_string

                if not self.kwargs['without_arg_transfer']:
                    theme, is_default_theme = self.theme
                    language, is_default_language = self.language

                    if not is_default_theme:
                        return_url += '&theme=' + theme
                    if not is_default_language:
                        return_url += '&language=' + language
                    if not is_default_choice:
                        return_url += '&wc=' + str(int(without_cookies))

                g.captchaify_page = True
                g.captchaify_no_new_cookies = True
                return redirect(return_url)

            if not without_redirect and self.kwargs['as_route']:
                return redirect(self._create_route_url('captcha'))

            if is_failed_captcha and not client_ip is None:
                self._add_failed_captcha_attempt(client_ip)

            return self._render_captcha(
                is_error = is_failed_captcha,
                return_path = quote(return_path),
                without_redirect = True
            )
        except Exception as exc:
            handle_exception(exc)

        return self._render_block()


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


    def _load_dataset(self, dataset_path: str) -> dict:
        """
        Loads a dataset from the specified path.

        :param dataset_path: The path to the dataset.
        :return: Returns the dataset dict
        """

        if dataset_path in self.loaded_datasets:
            return self.loaded_datasets[dataset_path]

        dataset = JSON.load(dataset_path)

        dataset_size = self.kwargs['dataset_size']
        if dataset_size == 'full':
            self.loaded_datasets[dataset_path] = dataset
            return dataset

        if isinstance(dataset_size, str):
            dataset_size = DATASET_SIZES.get(dataset_size, (20, 100))

        new_dataset = {}
        if not len(dataset.keys()) == dataset_size[1]:
            max_dataset_keys = min(len(dataset.keys()), dataset_size[1])

            for _ in range(max_dataset_keys):
                random_keyword = secrets.choice(list(dataset.keys()))
                while random_keyword in new_dataset:
                    random_keyword = secrets.choice(list(dataset.keys()))

                new_dataset[random_keyword] = dataset[random_keyword]

        dataset = {keyword: images[:dataset_size[0]]
                   for keyword, images in new_dataset.items()}

        self.loaded_datasets[dataset_path] = dataset
        return dataset


    def _get_captcha_data(self) -> dict:
        """
        Get the captcha data from the request.

        :return: The captcha data.
        """

        url_path = urlparse(self._req_info.get_url()).path
        client_ip = self.ip

        config = self._current_configuration
        captcha_type = config['captcha_type'].split('_')[0]
        captcha_id = generate_random_string(30)

        captcha_data = {
            "id": captcha_id, "type": captcha_type,
            "ip": ('None' if client_ip is None else Hashing().hash(client_ip)),
            "user_agent": Hashing().hash(self.user_agent),
            "path": Hashing().hash(url_path), "time": str(int(time())),
            "hardness": config['hardness']
        }

        return captcha_data


    def _find_template(self, template: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Finds the path to the template file.

        :param template: The name of the template
        :return: A tuple containing the path to the template file and the name of the template file
        """

        template_dir = self._current_configuration['template_dir']

        page_path = None
        file_name = None

        for file_name in os.listdir(template_dir):
            if file_name.startswith(template):
                page_path = os.path.join(template_dir, file_name)
                break

        return page_path, file_name


    def _verify_captcha_token(self, captcha_token:\
                             Optional[str] = None) -> Union[bool, bool]:
        """
        Verify the captcha token.

        :param captcha_token: The captcha token to be verified
        :return: A tuple containing the verification result and the captcha type
        """

        is_failed_captcha = False

        try:
            url_path = urlparse(request.url).path
            client_ip = self.ip

            request_data = request.form if request.method.lower() == 'post' else request.args
            request_captcha_token = request_data.get('ct', None)

            if request_captcha_token is None and captcha_token is None:
                return False, False

            if captcha_token is None:
                captcha_token = request_captcha_token

            decrypted_token_data = self.sses.decrypt(captcha_token)
            if decrypted_token_data is None:
                return False, False

            captcha_id = decrypted_token_data['id']
            if self._was_already_used(captcha_id):
                return False, False

            if int(time()) - int(decrypted_token_data['time']) > 120:
                return False, False

            if decrypted_token_data['hardness'] < self._current_configuration['hardness']:
                return False, False

            token_captcha_type = decrypted_token_data['type']
            if token_captcha_type in ['oneclick', 'multiclick']:
                original_keyword = decrypted_token_data['keyword']

                if token_captcha_type == 'oneclick':
                    keywords = decrypted_token_data['other_keywords']
                    if str(keywords.index(original_keyword))\
                        != str(request.args.get('ci')):
                        is_failed_captcha = True

                if token_captcha_type == 'multiclick':
                    request_indices = []
                    for key, value in request_data.items():
                        if (
                            value.lower() == '1' and
                            key.startswith('ci') and
                            len(key) == 3
                        ):
                            index = int(key[-1])
                            request_indices.append(index)

                    if sorted(request_indices) != sorted(decrypted_token_data['correct']):
                        is_failed_captcha = True
            elif token_captcha_type in [
                'recaptcha', 'hcaptcha', 'turnstile',
                'friendlycaptcha', 'altcha', 'trueclick'
                ]:

                if token_captcha_type == 'trueclick':
                    config = self._current_configuration
                    dataset_dir, hardness = config['dataset_dir'], config['hardness']

                    trueclick = TrueClick(dataset_dir, hardness)
                    if not trueclick.is_trueclick_valid():
                        is_failed_captcha = True
                else:
                    third_party_name = {
                        'recaptcha': 'g-recaptcha', 'turnstile': 'cf-turnstile',
                        'hcaptcha': 'h-captcha', 'friendlycaptcha': 'frc-captcha'
                    }.get(token_captcha_type)

                    if token_captcha_type != 'altcha':
                        response_or_solution = 'solution'\
                            if token_captcha_type == 'friendlycaptcha' else 'response'

                        key = third_party_name + '-' + response_or_solution
                        if request.method.lower() == 'post':
                            response_data = request.form.get(key)
                        else:
                            response_data = request.args.get(key)

                        config = self._current_configuration
                        secret = {
                            "recaptcha": config['recaptcha_secret'],
                            "hcaptcha": config['hcaptcha_secret'],
                            "turnstile": config['turnstile_secret'],
                            "friendlycaptcha": config['friendly_secret']
                        }.get(token_captcha_type, None)

                        post_data = {
                            'secret': secret,
                            response_or_solution: response_data
                        }

                        api_url = CAPTCHA_THIRD_PARTIES_API_URLS.get(token_captcha_type)

                        post_data_encoded = urllib.parse.urlencode(post_data).encode('utf-8')
                        req = urllib.request.Request(api_url, data=post_data_encoded)

                        timeout = 3
                        try:
                            with urllib.request.urlopen(req, timeout=timeout) as response:
                                response_data = response.read()
                                response_json = json.loads(response_data)

                            if not validate_captcha_response(
                                response_json, get_domain_from_url(self._req_info.get_url())):
                                is_failed_captcha = True
                        except Exception:
                            is_failed_captcha = True

                    else:
                        if request.method.lower() == 'post':
                            response_data = request.form.get('altcha_response')
                        else:
                            response_data = request.args.get('altcha_response')

                        if not self.altcha.verify_challenge(response_data):
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
                comparison_path = Hashing().compare(
                    url_path, decrypted_token_data['path']
                )
                comparison_ip = True if client_ip is None else\
                Hashing().compare(
                    client_ip, decrypted_token_data['ip']
                )
                comparison_user_agent = Hashing().compare(
                    self.user_agent, decrypted_token_data['user_agent']
                )

                if not comparison_path or (not comparison_ip and not comparison_user_agent):
                    is_failed_captcha = True
                else:
                    return True, False
        except Exception as exc:
            handle_exception(exc)

            return False, True

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
            elif request.form.get('captcha') is not None:
                captcha_string = request.form.get('captcha')

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

                    if not int(time()) - int(ip_data['time']) > self.kwargs['verification_age'] and\
                            ip == client_ip and user_agent == self.user_agent:
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
            client_ip = self._req_info.get_ip()
            if client_ip is None:
                client_ip = 'None'

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


    def _add_failed_captcha_attempt(self, client_ip: Optional[str] = None) -> None:
        """
        Add a failed captcha attempt for the specified client IP.

        :param client_ip: The IP address of the client
                          for which to add the failed attempt.
        """

        if client_ip is None:
            client_ip = 'None'

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

        :param return_path: The path to redirect to if the captcha is valid
        :return: None or redirect to a url + args
        """

        captcha_id = generate_random_string(8, with_punctuation=False)
        captcha_token = generate_random_string(22, with_punctuation=False)

        solved_captchas = PICKLE.load(SOLVED_CAPTCHAS_PATH)

        while any(Hashing().compare(captcha_id, hashed_id)\
                    for hashed_id, _ in solved_captchas.items()):
            captcha_id = generate_random_string(8, with_punctuation=False)

        symcrypto = SymmetricCrypto(self.captcha_secret)

        client_ip = self.ip
        data = {
            'time': int(time()),
            'ip': ('None' if client_ip is None else symcrypto.encrypt(client_ip)),
            'user_agent': symcrypto.encrypt(self.user_agent),
        }

        solved_captchas = PICKLE.load(SOLVED_CAPTCHAS_PATH)

        solved_captchas[Hashing().hash(captcha_id)] = data

        PICKLE.dump(solved_captchas, SOLVED_CAPTCHAS_PATH)

        g.captchaify_captcha = captcha_id + captcha_token

        if self.kwargs['as_route']:
            url = get_return_url(return_path, request)
        else:
            url = remove_all_args_from_url(self._req_info.get_url())

        without_cookies, is_default_choice = self.without_cookies

        char = get_char(url)
        if without_cookies:
            url += char + 'captcha=' + quote(str(captcha_id + captcha_token))

        if not self.kwargs['without_arg_transfer'] and without_cookies:
            theme, is_default_theme = self.theme
            language, is_default_language = self.language

            if not is_default_theme:
                url += get_char(url) + 'theme=' + theme
            if not is_default_language:
                url += get_char(url) + 'language=' + language
            if not is_default_choice:
                url += get_char(url) + 'wc=1'

        g.captchaify_page = True
        g.captchaify_no_new_cookies = True
        return redirect(url)


    def _create_route_url(self, template: str, without_return_path: Optional[bool] = None) -> str:
        """
        Creates a route URL with the specified template, including return path,
        theme, and language parameters.

        :param template: The template to be used in constructing the URL.
        :param without_return_path: Whether the return path should be added to the request
        :return: The constructed route URL.
        """

        if not isinstance(without_return_path, bool):
            if request.path in self._own_routes:
                without_return_path = True

        return_path = get_return_path(request)
        if return_path is None:
            return_path = quote(
                extract_path_and_args(
                    remove_args_from_url(self._req_info.get_url(),
                        ['theme', 'language', 'captcha',
                         'return_path', 'wc', 'js']
                    )
                )
            )

        redirect_url = f'/{template}' + self.route_id +\
            ('?return_path=' + return_path if not without_return_path\
              and return_path != '/' else '')

        theme, is_default_theme = self.theme
        language, is_default_language = self.language
        without_cookies, is_default_choice = self.without_cookies

        if not is_default_theme:
            redirect_url += get_char(redirect_url) + 'theme=' + theme
        if not is_default_language:
            redirect_url += get_char(redirect_url) + 'language=' + language
        if not is_default_choice and without_cookies:
            redirect_url += get_char(redirect_url) + 'wc=' + str(int(without_cookies))

        captcha_string = None
        if request.args.get('captcha') is not None:
            captcha_string = request.args.get('captcha')
        elif request.cookies.get('captcha') is not None:
            captcha_string = request.cookies.get('captcha')
        elif request.form.get('captcha') is not None:
            captcha_string = request.form.get('captcha')

        if captcha_string is not None:
            redirect_url += '&captcha=' + captcha_string

        return redirect_url
