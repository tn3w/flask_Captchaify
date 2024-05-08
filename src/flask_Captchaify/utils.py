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

import secrets
import re
import io
import random
from base64 import urlsafe_b64encode, urlsafe_b64decode, b64decode, b64encode
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, quote
import gzip
import hashlib
import os
import unicodedata
import threading
import json
from typing import Union, Optional, Final, Tuple
from time import time
from PIL import Image, ImageFilter
import numpy as np
import ipaddress
from flask import request, g, Request
from jinja2 import Environment, FileSystemLoader, select_autoescape, Undefined
from googletrans import Translator
from bs4 import BeautifulSoup, Tag
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import requests


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Create the file test.env in the `src/flask_Captchaify` folder if you do
# not want to install the module with pip but want to import it from this
# folder, e.g. to display code changes directly.
if not os.path.exists(os.path.join(CURRENT_DIR, 'test.env')):
    import pkg_resources

def get_work_dir():
    if os.path.exists(os.path.join(CURRENT_DIR, 'test.env')):
        return CURRENT_DIR

    return pkg_resources.resource_filename('flask_Captchaify', '')


WORK_DIR: Final[str] = get_work_dir()
DATA_DIR: Final[str] = os.path.join(WORK_DIR, 'data')
ASSETS_DIR: Final[str] = os.path.join(WORK_DIR, 'assets')

TOR_EXIT_IPS_LIST_PATH: Final[str] = os.path.join(DATA_DIR, 'tor-exit-ips.json')
STOPFORUMSPAM_CACHE_PATH: Final[str] = os.path.join(DATA_DIR, 'stopforumspam-cache.json')
IP_API_CACHE_PATH: Final[str] = os.path.join(DATA_DIR, 'ipapi-cache.json')

ALL_THEMES: Final[list] = ['dark', 'light']
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
USER_AGENTS: Final[list] =\
    [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'+
        ' (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.3',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/'+
        '605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.1',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/5'+
        '37.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.3',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/6'+
        '05.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.1',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/6'+
        '05.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.1',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/6'+
        '05.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.1'
]
IP_INFO_KEYS: Final[list] = ['continent', 'continentCode', 'country', 'countryCode',
                'region', 'regionName', 'city', 'district', 'zip', 'lat',
                'lon', 'timezone', 'offset', 'currency', 'isp', 'org', 'as',
                'asname', 'reverse', 'mobile', 'proxy', 'hosting', 'time']
TOR_EXIT_IPS_URL: Final[str] = 'https://check.torproject.org/torbulkexitlist'


def rearrange_url(url: str, args_to_remove: list) -> str:
    """
    Rearrange the arguments of a URL by removing specified arguments and moving others to the beginning.

    :param url: The URL to rearrange.
    :param args_to_remove: A list of arguments to remove from the URL.
    :return: The rearranged URL.
    """

    parsed_url = urlparse(url)

    args = parse_qs(parsed_url.query)

    for arg in args_to_remove:
        args.pop(arg, None)

    new_query_string = urlencode(args, doseq=True)

    rearranged_url = urlunparse(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path,
         parsed_url.params, new_query_string, parsed_url.fragment)
    )

    return rearranged_url


def get_domain_from_url(url: str) -> str:
    """
    Extracts the domain from a given URL.

    :param url: The URL from which to extract the domain.
    :return: The domain extracted from the URL.
    """

    parsed_url = urlparse(url)
    domain_parts = parsed_url.netloc.split('.')
    if len(domain_parts) > 2:
        domain = '.'.join(domain_parts[-2:])
    else:
        domain = parsed_url.netloc
    return domain


def get_path_from_url(url: str) -> Optional[str]:
    """
    Extracts the path component from a given URL.

    :param url: The URL from which to extract the path.
    :return: The path component of the URL, or None if the URL
             is invalid or does not contain a path.
    """

    parsed_url = urlparse(url)
    if isinstance(parsed_url.path, str):
        return parsed_url.path

    return None


def generate_random_string(length: int, with_punctuation: bool = True, with_letters: bool = True):
    """
    Generates a random string

    :param length: The length of the string
    :param with_punctuation: Whether to include special characters
    :param with_letters: Whether letters should be included
    """

    characters = '0123456789'

    if with_punctuation:
        characters += r"!\'#$%&'()*+,-./:;<=>?@[\]^_`{|}~"

    if with_letters:
        characters += 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string


def random_user_agent() -> str:
    """
    Generates a random user agent to bypass Python blockades
    """

    return secrets.choice(USER_AGENTS)


def shorten_ipv6(ip_address: str) -> str:
    """
    Minimizes each ipv6 Ip address to be able to compare it with others
    
    :param ip_address: An ipv4 or ipv6 Ip address
    """

    try:
        return str(ipaddress.IPv6Address(ip_address).compressed)
    except ValueError:
        return ip_address


def is_valid_ip(ip_address: Optional[str] = None,
                without_filter: bool = False) -> bool:
    """
    Checks whether the current Ip is valid
    
    :param ip_address: Ipv4 or Ipv6 address (Optional)
    """

    if not without_filter:
        if not isinstance(ip_address, str)\
            or ip_address is None\
            or ip_address in UNWANTED_IPS:
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


def get_random_image(all_images: list[str]) -> str:
    """
    Retrieve a random image path from the list, decode it from base64, and return it.

    :param all_images: A list of image paths encoded as base64 strings.
    :return: The decoded image data as a string.
    """

    random_image = random.choice(all_images)
    decoded_image = b64decode(random_image.encode('utf-8'))
    decompressed_data = gzip.decompress(decoded_image)

    return decompressed_data


def convert_image_to_base64(image_data: bytes) -> str:
    """
    Converts an image into Base64 Web Format

    :param image_data: The data of an image file in webp format
    """

    encoded_image = b64encode(image_data).decode('utf-8')

    data_url = f'data:image/webp;base64,{encoded_image}'

    return data_url


def manipulate_image_bytes(image_data: bytes, is_small: bool = False) -> bytes:
    """
    Manipulates an image represented by bytes to create a distorted version.

    :param image_data: The bytes representing the original image.
    :return: The bytes of the distorted image.
    """
    img = Image.open(io.BytesIO(image_data))

    width, height = img.size

    x_shifts = [[random.randint(-2, 3) for _ in range(width)] for _ in range(height)]
    y_shifts = [[random.randint(-2, 3) for _ in range(width)] for _ in range(height)]

    shifted_img = Image.new('RGB', (width, height))
    for y in range(height):
        for x in range(width):
            new_x = (x + x_shifts[y][x]) % width
            new_y = (y + y_shifts[y][x]) % height
            shifted_img.putpixel((x, y), img.getpixel((new_x, new_y)))

    shifted_img = shifted_img.convert('HSV')

    saturation_factor = 1.02
    value_factor = 0.99
    h, s, v = shifted_img.split()

    s = s.point(lambda i: min(255, i * saturation_factor))
    v = v.point(lambda i: max(0, i * value_factor))

    shifted_img = Image.merge('HSV', (h, s, v))

    shifted_img = shifted_img.convert('RGB')
    shifted_img = shifted_img.filter(ImageFilter.GaussianBlur(radius=0.2))

    size = 100 if is_small else 200
    shifted_img = shifted_img.resize((size, size), Image.LANCZOS)

    output_bytes = io.BytesIO()
    shifted_img.save(output_bytes, format='WebP')
    output_bytes.seek(0)
    return output_bytes.read()


def get_client_ip() -> Union[Optional[str], bool]:
    """
    Get the client IP in v4 or v6
    """

    invalid_ips = []

    client_ip = request.remote_addr
    invalid_ips.append(client_ip)
    if is_valid_ip(client_ip):
        client_ip = shorten_ipv6(client_ip)
        return client_ip, False

    other_client_ips = [
        request.environ.get('HTTP_X_REAL_IP', None),
        request.environ.get('REMOTE_ADDR', None),
        request.environ.get('HTTP_X_FORWARDED_FOR', None),
    ]

    for client_ip in other_client_ips:
        invalid_ips.append(client_ip)
        if is_valid_ip(client_ip):
            client_ip = shorten_ipv6(client_ip)
            return client_ip, False

    try:
        client_ip = request.headers.getlist('X-Forwarded-For')[0].rpartition(' ')[-1]
    except (IndexError, AttributeError, ValueError, TypeError):
        pass
    else:
        invalid_ips.append(client_ip)
        if is_valid_ip(client_ip):
            client_ip = shorten_ipv6(client_ip)
            return client_ip, False

    headers_to_check = [
        'X-Forwarded-For',
        'X-Real-Ip',
        'CF-Connecting-IP',
        'True-Client-Ip',
    ]

    for header in headers_to_check:
        if header in request.headers:
            client_ip = request.headers[header]
            client_ip = client_ip.split(',')[0].strip()
            invalid_ips.append(client_ip)
            if is_valid_ip(client_ip):
                client_ip = shorten_ipv6(client_ip)
                return client_ip, False

    for invalid_ip in invalid_ips:
        if isinstance(invalid_ip, str):
            if is_valid_ip(invalid_ip, True):
                return invalid_ip, True

    for invalid_ip in invalid_ips:
        if isinstance(invalid_ip, str):
            return invalid_ip, True

    return None, False


def remove_args_from_url(url: str) -> str:
    """
    Removes query parameters from the given URL and returns the modified URL.

    :param url: The input URL
    """

    parsed_url = urlparse(url)

    scheme, netloc, path, params, query, fragment = parsed_url

    query_args = parse_qs(query)
    query_args.clear()

    url_without_args = urlunparse((scheme, netloc, path, params, '', fragment))

    return url_without_args


def normalize_string(text: str) -> str:
    """
    Normalize a string by removing diacritics and converting to lowercase.

    :param text: The input text to normalize.
    :return: The normalized text without diacritics and in lowercase.
    """

    return ''.join(char for char in unicodedata.normalize('NFD', text)\
                   if unicodedata.category(char) != 'Mn' and char.isalnum()).lower()


def levenshtein_distance(text1: str, text2: str) -> int:
    """
    Compute the Levenshtein distance between two strings.

    :param text1: The first input string.
    :param text2: The second input string.
    :return: The Levenshtein distance between the two input strings.
    """

    if len(text1) < len(text2):
        return levenshtein_distance(text1 = text2, text2 = text1)

    if len(text2) == 0:
        return len(text1)

    previous_row = range(len(text2) + 1)
    for i, c1 in enumerate(text1):
        current_row = [i + 1]
        for j, c2 in enumerate(text2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def search_languages(query: str, languages: list[dict]) -> list[dict]:
    """
    Search for languages in the list based on the similarity of their names to the query.

    :param query: The query string to search for.
    :param languages: The list of dictionaries containing language information.
    :return: A list of dictionaries containing the languages sorted by similarity to the query.
    """

    normalized_query = normalize_string(query)
    if normalized_query.strip() == '':
        return languages

    results = []
    for language in languages:
        normalized_language_name = normalize_string(language['name'])
        distance = levenshtein_distance(normalized_query, normalized_language_name)

        if normalized_query in normalized_language_name\
            or (distance <= 2 and not language['code'] == 'ja'):
            results.append(language)

    results.sort(key=lambda x: levenshtein_distance(normalized_query, normalize_string(x['name'])))

    return results


file_locks = {}

class JSON:
    """
    Class for loading / saving JavaScript Object Notation (= JSON)
    """

    @staticmethod
    def load(file_name: str, default: Union[dict, list] = None) -> Union[dict, list]:
        """
        Function to load a JSON file securely.

        :param file_name: The JSON file you want to load
        :param default: Returned if no data was found
        """

        if not os.path.isfile(file_name):
            if not default is None:
                return default
            return {}

        if file_name not in file_locks:
            file_locks[file_name] = threading.Lock()

        with file_locks[file_name]:
            with open(file_name, 'r', encoding = 'utf-8') as file:
                data = json.load(file)
            return data


    @staticmethod
    def dump(data: Union[dict, list], file_name: str) -> bool:
        """
        Function to save a JSON file securely.
        
        :param data: The data to be stored should be either dict or list
        :param file_name: The file to save to
        """

        file_directory = os.path.dirname(file_name)
        if not os.path.isdir(file_directory):
            return False

        if file_name not in file_locks:
            file_locks[file_name] = threading.Lock()

        with file_locks[file_name]:
            with open(file_name, 'w', encoding = 'utf-8') as file:
                json.dump(data, file)
        return True


LANGUAGES = JSON.load(os.path.join(ASSETS_DIR, 'languages.json'), [])
LANGUAGE_CODES = [language['code'] for language in LANGUAGES]
TRANSLATIONS_FILE_PATH = os.path.join(DATA_DIR, 'translations.json')
translator = Translator()


def render_template(template_dir: str, file_name: str,
                    request: Request, template_language:\
                    Optional[str] = None, **args) -> str:
    """
    Renders a template file into HTML content, optionally translating it to the specified language.

    :param template_dir: The directory path where template files are located.
    :param file_name: The name of the template file to render.
    :param request: The request object providing information about the client's language preference.
    :param template_language: The language code specifying the language of the template content. 
                              If not provided, defaults to 'en' (English).
    :param **args: Additional keyword arguments to pass to the template rendering function.

    :return: The rendered HTML content of the template.
    """

    if template_language is None:
        template_language = "en"

    client_theme, is_default_theme = WebPage.client_theme(request)
    client_language, is_default_language = WebPage.client_language(request)

    args["theme"] = client_theme
    args["is_default_theme"] = is_default_theme
    args["language"] = client_language
    args["is_default_language"] = is_default_language
    args["alternate_languages"] = LANGUAGE_CODES

    args["current_url"] = rearrange_url(WebPage.client_url(request), ['ct', 'ci', 'captcha'])
    args["current_url_without_ccl"] = rearrange_url(args["current_url"], ['ccl'])
    args["current_url_without_theme"] = rearrange_url(args["current_url"], ['theme'])
    args["current_url_without_language"] = rearrange_url(args["current_url"], ['language'])

    html = WebPage.render_template(template_dir, file_name, html = None, **args)
    html = WebPage.translate(html, template_language, client_language)
    html = WebPage.minimize(html)

    return html


class WebPage:
    """
    Class with useful tools for WebPages
    """


    @staticmethod
    def client_theme(request: Request, default: Optional[str] = None) -> Tuple[str, bool]:
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
            if default is None:
                default = "dark"

            return default, True

        return theme, False


    @staticmethod
    def client_language(request: Request) -> Tuple[str, bool]:
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
                return preferred_language, True
        else:
            return chosen_language, False

        return 'en', True


    @staticmethod
    def client_url(request: Request) -> str:
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


    @staticmethod
    def _minimize_tag_content(html: str, tag: str) -> str:
        """
        Minimizes the content of a given tag
        
        :param html: The HTML page where the tag should be minimized
        :param tag: The HTML tag e.g. `script` or `style`
        """

        tag_pattern = rf'<{tag}\b[^>]*>(.*?)<\/{tag}>'

        def minimize_tag_content(match: re.Match):
            content = match.group(1)
            content = re.sub(r'\s+', ' ', content)
            return f'<{tag}>{content}</{tag}>'

        return re.sub(tag_pattern, minimize_tag_content, html, flags=re.DOTALL | re.IGNORECASE)


    @staticmethod
    def minimize(html: str) -> str:
        """
        Minimizes an HTML page

        :param html: The content of the page as html
        """

        html = re.sub(r'<!--(.*?)-->', '', html, flags=re.DOTALL)
        html = re.sub(r'\s+', ' ', html)

        html = WebPage._minimize_tag_content(html, 'script')
        html = WebPage._minimize_tag_content(html, 'style')
        return html


    @staticmethod
    def _translate_text(text_to_translate: str, from_lang: str, to_lang: str) -> str:
        """
        Function to translate a text based on a translation file

        :param text_to_translate: The text to translate
        :param from_lang: The language of the text to be translated
        :param to_lang: Into which language the text should be translated
        """

        text_to_translate = text_to_translate.strip('\n ')

        if from_lang == to_lang or not text_to_translate:
            return text_to_translate

        translations = JSON.load(TRANSLATIONS_FILE_PATH, [])

        for translation in translations:
            if translation["text_to_translate"] == text_to_translate\
                and translation["from_lang"] == from_lang\
                    and translation["to_lang"] == to_lang:
                return translation["translated_output"]

        translator = Translator()

        try:
            translated_output = translator.translate(
                text_to_translate, src=from_lang, dest=to_lang
                ).text

            if translated_output is None:
                return text_to_translate
        except (UnicodeEncodeError, UnicodeDecodeError,
                ValueError, AttributeError, TypeError):
            return text_to_translate

        translation = {
            "text_to_translate": text_to_translate, 
            "from_lang": from_lang,
            "to_lang": to_lang, 
            "translated_output": translated_output
        }
        translations.append(translation)

        JSON.dump(translations, TRANSLATIONS_FILE_PATH)

        return translated_output


    @staticmethod
    def translate(html: str, from_lang: str, to_lang: str) -> str:
        """
        Function to translate a page into the correct language

        :param html: The content of the page as html
        :param from_lang: The language of the text to be translated
        :param to_lang: Into which language the text should be translated
        """

        def translate_tag(html_tag: Tag, from_lang: str, to_lang: str):
            for tag in html_tag.find_all(text=True):
                if hasattr(tag, 'attrs'):
                    if 'ntr' in tag.attrs:
                        continue

                if tag.parent.name not in ['script', 'style']:
                    translated_text = WebPage._translate_text(tag, from_lang, to_lang)
                    tag.replace_with(translated_text)

            translated_html = str(html_tag)
            return translated_html

        soup = BeautifulSoup(html, 'html.parser')

        tags = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5',
                              'h6', 'a', 'p', 'button'])
        for tag in tags:
            if str(tag) and 'ntr' not in tag.attrs:
                translate_tag(tag, from_lang, to_lang)

        inputs = soup.find_all('input')
        for input_tag in inputs:
            if input_tag.has_attr('placeholder') and 'ntr' not in input_tag.attrs:
                input_tag['placeholder'] = WebPage._translate_text(
                    input_tag['placeholder'].strip(), from_lang, to_lang
                    )

        head_tag = soup.find('head')
        if head_tag:
            title_element = head_tag.find('title')
            if title_element:
                title_element.string = WebPage._translate_text(
                    title_element.text.strip(), from_lang, to_lang
                    )

            meta_title = head_tag.find('meta', attrs={'name': 'title'})
            if meta_title and 'content' in meta_title.attrs:
                meta_title['content'] = WebPage._translate_text(
                    meta_title['content'].strip(), from_lang, to_lang
                )

            meta_description = head_tag.find('meta', attrs={'name': 'description'})
            if meta_description and 'content' in meta_description.attrs:
                meta_description['content'] = WebPage._translate_text(
                    meta_description['content'].strip(), from_lang, to_lang
                )

            meta_keywords = head_tag.find('meta', attrs={'name': 'keywords'})
            if meta_keywords and 'content' in meta_keywords.attrs:
                meta_keywords['content'] = WebPage._translate_text(
                    meta_keywords['content'].strip(), from_lang, to_lang
                )

        translated_html = soup.prettify()
        return translated_html


    @staticmethod
    def add_args(html: str, request: Request, **args) -> str:
        """
        Adds arguments to links and forms in HTML based on the request.

        :param html: The HTML content to which arguments need to be added.
        :param request: The Flask Request object containing information about the current request.
        :return: The HTML content with arguments added to links and forms.
        """

        theme, is_default_theme = WebPage.client_theme(request)
        if not is_default_theme:
            args['theme'] = theme

        language, is_default_language = WebPage.client_language(request)
        if not is_default_language:
            args['language'] = language

        soup = BeautifulSoup(html, 'html.parser')

        def has_argument(url, arg):
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            return arg in query_params

        for anchor in soup.find_all('a'):
            if not 'href' in anchor.attrs:
                continue

            if '://' in anchor['href']:
                anchor_host = get_domain_from_url(anchor['href'])
                if anchor_host != get_domain_from_url(request.url):
                    continue
            elif not anchor['href'].startswith('/') and \
                not anchor['href'].startswith('#') and \
                    not anchor['href'].startswith('?') and \
                        not anchor['href'].startswith('&'):
                continue

            for arg, content in args.items():
                if arg == 'template':
                    anchor_path = get_path_from_url(anchor['href'])
                    if isinstance(anchor_path, str):
                        if not '/signature' in anchor_path:
                            continue

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

        html_with_args = soup.prettify()
        return html_with_args


    @staticmethod
    def render_template(template_dir: str, file_name: Optional[str] = None,
                        html: Optional[str] = None, **args) -> str:
        """
        Function to render a HTML template (= insert arguments / translation / minimization)

        :param template_dir: The directory path where template files are located.
        :param file_name: The name of the template file to render. (Optional)
        :param html: The content of the page as html. (Optional)
        :param args: Arguments to be inserted into the WebPage with Jinja2.
        """

        file_path = os.path.join(template_dir, file_name)

        if file_path is None and html is None:
            raise ValueError("Arguments 'file_path' and 'html' are None")

        if not file_path is None:
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"File `{file_path}` does not exist")

        class SilentUndefined(Undefined):
            """
            Class to not get an error when specifying a non-existent argument
            """

            def _fail_with_undefined_error(self, *args, **kwargs):
                return None

        loader = FileSystemLoader(template_dir)
        env = Environment(
            loader = loader,
            autoescape=select_autoescape(['html', 'xml']),
            undefined=SilentUndefined
        )

        if html is None:
            with open(file_path, "r", encoding = "utf-8") as file:
                html = file.read()

        template = env.from_string(html)

        html = template.render(**args)

        return html


class SymmetricCrypto:
    """
    Implementation of symmetric encryption with AES
    """

    def __init__(self, password: Optional[str] = None, salt_length: int = 32):
        """
        :param password: A secure encryption password, should be at least 32 characters long
        :param salt_length: The length of the salt, should be at least 16
        """

        if password is None:
            password = secrets.token_urlsafe(64)

        self.password = password.encode()
        self.salt_length = salt_length


    def encrypt(self, plain_text: str) -> Optional[str]:
        """
        Encrypts a text

        :param plaintext: The text to be encrypted
        """

        salt = secrets.token_bytes(self.salt_length)

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        iv = secrets.token_bytes(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_text.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return urlsafe_b64encode(salt + iv + ciphertext).decode()


    def decrypt(self, cipher_text: str) -> Optional[str]:
        """
        Decrypts a text

        :param ciphertext: The encrypted text
        """

        try:
            cipher_text = urlsafe_b64decode(cipher_text.encode())

            salt, iv, cipher_text = cipher_text[:self.salt_length],\
                cipher_text[self.salt_length:self.salt_length + 16],\
                    cipher_text[self.salt_length + 16:]

            kdf_ = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf_.derive(self.password)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
            plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

            return plaintext.decode()
        except (ValueError, TypeError, InvalidKey):
            return None


class Hashing:
    """
    Implementation for hashing
    """

    def __init__(self, salt: Optional[str] = None):
        """
        :param salt: The salt, makes the hashing process more secure (Optional)
        """

        self.salt = salt


    def hash(self, plain_text: str, hash_length: int = 8) -> str:
        """
        Function to hash a plaintext

        :param plain_text: The text to be hashed
        :param hash_length: The length of the returned hashed value
        """

        salt = self.salt
        if salt is None:
            salt = secrets.token_hex(hash_length)
        plain_text = salt + plain_text

        hash_object = hashlib.sha256(plain_text.encode())
        hex_dig = hash_object.hexdigest()

        return hex_dig + '//' + salt


    def compare(self, plain_text: str, hash_string: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plain_text: The text that was hashed
        :param hash: The hashed value
        """

        salt = self.salt
        if '//' in hash_string:
            hash_string, salt = hash_string.split('//')

        hash_length = len(hash_string)

        comparison_hash = Hashing(salt=salt).hash(plain_text,
                                                  hash_length = hash_length).split('//')[0]

        return comparison_hash == hash_string


class SSES:
    """
    Space-saving encryption scheme (SSES) for encrypting data without keys and decrypting with keys.
    """

    def __init__(self, symmetric_crypto: SymmetricCrypto, separator: str = '--') -> None:
        """
        Initializes the SSES instance with the specified symmetric cryptography object and separator

        :param symmetric_crypto: The symmetric cryptography object to
                                 use for encryption and decryption.
        :param separator: The separator string to use for joining
                          values before encryption. Defaults to '--'.
        """

        self.symmetric_crypto = symmetric_crypto
        self.separator = separator


    def encrypt(self, data_dict: dict) -> str:
        """
        Encrypts the provided values.

        :param data_dict: Keyword arguments containing key-value pairs to encrypt.
        :return: The encrypted data.
        """

        values = list(data_dict.values())

        new_values = []
        for value in values:
            if isinstance(value, list) or isinstance(value, dict):
                value = '==json==' + json.dumps(value)
            new_values.append(value)

        text_data = self.separator.join(new_values)
        encrypted_data = self.symmetric_crypto.encrypt(text_data)

        return encrypted_data


    def decrypt(self, encrypted_data: str, dict_keys: Optional[list] = None) -> Union[dict, list]:
        """
        Decrypts the provided encrypted data.

        :param encrypted_data: The encrypted data to decrypt.
        :param dict_keys: A list of keys to use for forming a dictionary from decrypted values.
        :return: Decrypted data as either a dictionary (if dict_keys is provided) or a list.
        """

        decrypted_data = self.symmetric_crypto.decrypt(encrypted_data)
        if decrypted_data is None:
            return None

        values = decrypted_data.split(self.separator)

        if not isinstance(dict_keys, list) or len(dict_keys) == 0:
            return values

        data_dict = {}
        for i, dict_key in enumerate(dict_keys):
            if len(values) - 1 < i:
                break

            value = values[i]
            if value.startswith('==json=='):
                value = json.loads(value[8:])

            data_dict[dict_key] = value

        return data_dict


def request_tor_ips() -> list | None:
    """
    Requests and returns a list of Tor exit IPs. If the list has been recently fetched and cached,
    it returns the cached list, otherwise it fetches the list from the specified URL.

    :return: A list of Tor exit IPs.
    """

    tor_exit_ips = None
    if os.path.isfile(TOR_EXIT_IPS_LIST_PATH):
        ip_data = JSON.load(TOR_EXIT_IPS_LIST_PATH, None)
        if ip_data is not None:
            if isinstance(ip_data.get('time'), int):
                if int(time()) - int(ip_data.get('time', time())) <= 604800:
                    if isinstance(ip_data.get('ips'), list):
                        tor_exit_ips = ip_data.get('ips')

    if tor_exit_ips is None:
        tor_exit_ips = []
        try:
            response = requests.get(
                TOR_EXIT_IPS_URL,
                headers = {'User-Agent': random_user_agent()},
                timeout = 3
            )
        except (requests.exceptions.Timeout, requests.exceptions.RequestException):
            pass
        else:
            for line in response.text.split('\n'):
                tor_exit_ips.append(line.strip())

            JSON.dump(
                {'time': int(time()), 'ips': tor_exit_ips}
                , TOR_EXIT_IPS_LIST_PATH
            )

    return tor_exit_ips


def is_stopforumspam_spammer(ip_address: str) -> bool:
    """
    Checks if the given IP address is listed as a spammer on StopForumSpam.

    :param ip_address: The IP address to check.
    :return: True if the IP address is listed as a spammer, False otherwise.
    """

    stopforumspam_cache = JSON.load(STOPFORUMSPAM_CACHE_PATH)

    for hashed_ip, ip_content in stopforumspam_cache.items():
        comparison = Hashing().compare(ip_address, hashed_ip)
        if comparison:

            if not int(time()) - int(ip_content['time']) > 604800:
                return ip_content['spammer']
            break

    url = f'https://api.stopforumspam.org/api?ip={ip_address}&json'
    try:
        response = requests.get(
            url,
            headers = {'User-Agent': random_user_agent()},
            timeout = 3
        )
        response.raise_for_status()

        if response.status_code == 200:
            content = response.json()

            is_spammer = False
            if content.get('ip') is not None:
                if content['ip'].get('appears') is not None:
                    if content['ip']['appears'] > 0:
                        is_spammer = True

            hashed_ip_address = Hashing().hash(ip_address)

            stopforumspam_cache[hashed_ip_address] = {
                'spammer': is_spammer,
                'time': int(time())
            }

            JSON.dump(stopforumspam_cache, STOPFORUMSPAM_CACHE_PATH)
            return is_spammer

    except (requests.exceptions.Timeout, requests.exceptions.RequestException,
            json.JSONDecodeError):
        pass

    return False


def get_ip_info(ip_address: str) -> dict:
    """
    Function to query IP information with cache con ip-api.com

    :param ip_address: The client IP
    """

    ip_api_cache = JSON.load(IP_API_CACHE_PATH)

    for hashed_ip, crypted_data in ip_api_cache.items():
        comparison = Hashing().compare(ip_address, hashed_ip)
        if comparison:
            data = SymmetricCrypto(ip_address).decrypt(crypted_data)

            data_json = {}
            for i in range(23):
                data_json[IP_INFO_KEYS[i]] = {'True': True, 'False': False}\
                    .get(data.split('-&%-')[i], data.split('-&%-')[i])

            if int(time()) - int(data_json['time']) > 518400:
                del ip_api_cache[hashed_ip]
                break

            return data_json
    try:
        response = requests.get(
            f'http://ip-api.com/json/{ip_address}?fields=66846719',
            headers = {'User-Agent': random_user_agent()},
            timeout = 3
        )
        response.raise_for_status()
    except (requests.exceptions.Timeout, requests.exceptions.RequestException):
        return None

    if response.ok:
        response_json = response.json()
        if response_json['status'] == 'success':
            del response_json['status'], response_json['query']
            response_json['time'] = int(time())
            response_string = '-&%-'.join([str(value) for value in response_json.values()])

            crypted_response = SymmetricCrypto(ip_address).encrypt(response_string)
            hashed_ip = Hashing().hash(ip_address)

            ip_api_cache[hashed_ip] = crypted_response
            JSON.dump(ip_api_cache, IP_API_CACHE_PATH)

            return response_json

    return None
