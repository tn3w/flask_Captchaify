import pkg_resources
import secrets
from urllib.parse import urlparse, urlunparse, parse_qs
import ipaddress
from flask import request, g
from typing import Union, Optional
import os
import threading
import json
from jinja2 import Environment, select_autoescape, Undefined
from googletrans import Translator
import re
from bs4 import BeautifulSoup
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
from time import time
import requests

DATA_DIR = pkg_resources.resource_filename('flask_Captchaify', 'data')
ASSETS_DIR = pkg_resources.resource_filename('flask_Captchaify', 'assets')

def generate_random_string(length: int, with_punctuation: bool = True, with_letters: bool = True):
    """
    Generates a random string

    :param length: The length of the string
    :param with_punctuation: Whether to include special characters
    :param with_letters: Whether letters should be included
    """

    characters = "0123456789"

    if with_punctuation:
        characters += "!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"

    if with_letters:
        characters += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    
    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string

USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.3", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.3", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.1"]

def random_user_agent() -> str:
    "Generates a random user agent to bypass Python blockades"

    return secrets.choice(USER_AGENTS)

def shorten_ipv6(ip_address: str) -> str:
    """
    Minimizes each ipv6 Ip address to be able to compare it with others
    
    :param ip_address: An ipv4 or ipv6 Ip address
    """

    try:
        return str(ipaddress.IPv6Address(ip_address).compressed)
    except:
        return ip_address

def ipv4_to_ipv6(ipv4_address: str) -> Optional[str]:
    """
    Converts an ipv4 address to an ipv6 address

    :param ipv4_address: An Ip version 4 address
    """

    try:
        ipv4 = ipaddress.IPv4Address(ipv4_address)
    except ipaddress.AddressValueError:
        return None

    ipv6_minimized = ipaddress.IPv6Address("::ffff:" + str(ipv4)).compressed

    return str(ipv6_minimized)

def get_client_ip() -> str:
    "Get the client IP in v4 or v6"
    
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
            client_ip = shorten_ipv6(client_ip)
            return client_ip

    client_ip = request.remote_addr
    client_ip = shorten_ipv6(client_ip)
    return client_ip

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

file_locks = dict()

class JSON:
    "Class for loading / saving JavaScript Object Notation (= JSON)"

    @staticmethod
    def load(file_name: str, default: Union[dict, list] = dict()) -> Union[dict, list]:
        """
        Function to load a JSON file securely.

        :param file_name: The JSON file you want to load
        :param default: Returned if no data was found
        """

        if not os.path.isfile(file_name):
            if isinstance(default, list):
                return list()
            return dict()
        
        if file_name not in file_locks:
            file_locks[file_name] = threading.Lock()

        with file_locks[file_name]:
            with open(file_name, "r", encoding = "utf-8") as file:
                data = json.load(file)
            return data
    
    @staticmethod
    def dump(data: Union[dict, list], file_name: str) -> None:
        """
        Function to save a JSON file securely.
        
        :param data: The data to be stored should be either dict or list
        :param file_name: The file to save to
        """

        file_directory = os.path.dirname(file_name)
        if not os.path.isdir(file_directory):
            raise FileNotFoundError("Directory '" + file_directory + "' does not exist.")
        
        if file_name not in file_locks:
            file_locks[file_name] = threading.Lock()

        with file_locks[file_name]:
            with open(file_name, "w", encoding = "utf-8") as file:
                json.dump(data, file)

LANGUAGES = JSON.load(os.path.join(ASSETS_DIR, "languages.json"), list())
LANGUAGE_CODES = [language["code"] for language in LANGUAGES]
TRANSLATIONS_PATH = os.path.join(DATA_DIR, "translations.json")
translator = Translator()

class SilentUndefined(Undefined):
    "Class to not get an error when specifying a non-existent argument"

    def _fail_with_undefined_error(self, *args, **kwargs):
        return None

class WebPage:
    "Class with useful tools for WebPages"

    @staticmethod
    def _minimize_tag_content(html: str, tag: str) -> str:
        """
        Minimizes the content of a given tag
        
        :param html: The HTML page where the tag should be minimized
        :param tag: The HTML tag e.g. "script" or "style"
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
    def get_client_language(default: str = "en") -> str:
        """
        Function to get the language code of the client

        :param default: The value that is returned if no language can be found
        """

        preferred_language = request.accept_languages.best_match(LANGUAGE_CODES)

        if preferred_language != None:
            return preferred_language
        
        return default
    
    @staticmethod
    def _translate_text(text_to_translate: str, from_lang: str, to_lang: str) -> str:
        """
        Function to translate a text based on a translation file

        :param text_to_translate: The text to translate
        :param from_lang: The language of the text to be translated
        :param to_lang: Into which language the text should be translated
        """

        if from_lang == to_lang:
            return text_to_translate
        
        translations = JSON.load(TRANSLATIONS_PATH, list())
        
        for translation in translations:
            if translation["text_to_translate"] == text_to_translate and translation["from_lang"] == from_lang and translation["to_lang"] == to_lang:
                return translation["translated_output"]
        
        translated_output = translator.translate(text_to_translate, src=from_lang, dest=to_lang).text
            
        try:
            translated_output = translated_output.encode('latin-1').decode('unicode_escape')
        except:
            pass
        
        translation = {
            "text_to_translate": text_to_translate, 
            "from_lang": from_lang,
            "to_lang": to_lang, 
            "translated_output": translated_output
        }
        translations.append(translation)
        
        JSON.dump(translations, TRANSLATIONS_PATH)

        if to_lang in ["de", "en", "es", "fr", "pt", "it"]:
            translated_output = translated_output[0].upper() + translated_output[1:]
        
        return translated_output
    
    @staticmethod
    def translate(html: str, from_lang: str, to_lang: str) -> str:
        """
        Function to translate a page into the correct language

        :param html: The content of the page as html
        :param from_lang: The language of the text to be translated
        :param to_lang: Into which language the text should be translated
        """
        
        soup = BeautifulSoup(html, 'html.parser')

        def translate_htmlified_text(html_tag):
            try:
                new_soup = BeautifulSoup(str(html_tag), 'html.parser')
                outer_tag = new_soup.find(lambda tag: tag.find_all(recursive=False))

                text = ''.join(str(tag) for tag in outer_tag.contents)
            except:
                text = html_tag.text
                        
            if "<" in text:
                pattern = r'(<.*?>)(.*?)(<\/.*?>)'
        
                def replace(match):
                    tag_open, content, tag_close = match.groups()
                    processed_content = WebPage._translate_text(content, from_lang, to_lang)
                    return f'{tag_open}{processed_content}{tag_close}'
                
                modified_text = re.sub(pattern, replace, text)
            else:
                modified_text = WebPage._translate_text(text, from_lang, to_lang)
            return modified_text
        
        tags = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'p', 'button'])
        for tag in tags:
            if 'ntr' not in tag.attrs:
                translated_html = translate_htmlified_text(tag)
                tag.clear()
                tag.append(BeautifulSoup(translated_html, 'html.parser'))
        
        inputs = soup.find_all('input')
        for input_tag in inputs:
            if input_tag.has_attr('placeholder') and 'ntr' not in input_tag.attrs:
                input_tag['placeholder'] = WebPage._translate_text(input_tag['placeholder'], from_lang, to_lang)
        
        head_tag = soup.find('head')
        if head_tag:
            title_element = head_tag.find('title')
            if title_element:
                title_element.string = WebPage._translate_text(title_element.text, from_lang, to_lang)
        
        translated_html = soup.prettify()
        return translated_html
    
    @staticmethod
    def render_template(file_path: Optional[str] = None, html: Optional[str] = None, **args) -> str:
        """
        Function to render a HTML template (= insert arguments / translation / minimization)

        :param file_path: From which file HTML code should be loaded (Optional)
        :param html: The content of the page as html (Optional)
        :param args: Arguments to be inserted into the WebPage with Jinja2
        """

        if file_path is None and html is None:
            raise ValueError("Arguments 'file_path' and 'html' are None")
        
        if not file_path is None:
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"File `{file_path}` does not exist")
        
        env = Environment(
            autoescape=select_autoescape(['html', 'xml']),
            undefined=SilentUndefined
        )

        if html is None:
            with open(file_path, "r", encoding = "utf-8") as file:
                html = file.read()
                
        template = env.from_string(html)
        
        client_language = next((lang for lang in (
            request.args.get("captchaify_language"),
            request.cookies.get("language"),
            WebPage.get_client_language()
        ) if lang in LANGUAGE_CODES), None)

        args["language"] = client_language

        html = template.render(**args)
        html = WebPage.translate(html, "en", client_language)
        html = WebPage.minimize(html)

        g.ddosify_page = True

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

    def encrypt(self, plain_text: str) -> str:
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

    def decrypt(self, cipher_text: str) -> str:
        """
        Decrypts a text

        :param ciphertext: The encrypted text
        """

        cipher_text = urlsafe_b64decode(cipher_text.encode())

        salt, iv, cipher_text = cipher_text[:self.salt_length], cipher_text[self.salt_length:self.salt_length + 16], cipher_text[self.salt_length + 16:]

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

class Hashing:
    "Implementation for fast hashing"

    def __init__(self, salt: Optional[str] = None):
        ":param salt: The salt, makes the hashing process more secure (Optional)"

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

        return hex_dig + "//" + salt
    
    def compare(self, plain_text: str, hash: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plain_text: The text that was hashed
        :param hash: The hashed value
        """
        
        salt = self.salt
        if "//" in hash:
            hash, salt = hash.split("//")
        
        hash_length = len(hash)

        comparison_hash = Hashing(salt=salt).hash(plain_text, hash_length = hash_length).split("//")[0]

        return comparison_hash == hash

IP_API_CACHE_PATH = os.path.join(DATA_DIR, "ipapi-cache.json")
IP_INFO_KEYS = ['continent', 'continentCode', 'country', 'countryCode', 'region', 'regionName', 'city', 'district', 'zip', 'lat', 'lon', 'timezone', 'offset', 'currency', 'isp', 'org', 'as', 'asname', 'reverse', 'mobile', 'proxy', 'hosting', 'time']

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
                data_json[IP_INFO_KEYS[i]] = {"True": True, "False": False}.get(data.split("-&%-")[i], data.split("-&%-")[i])

            if int(time()) - int(data_json["time"]) > 518400:
                del ip_api_cache[hashed_ip]
                break

            return data_json
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_address}?fields=66846719",
            headers = {"User-Agent": random_user_agent()},
            timeout = 3
        )
        response.raise_for_status()
    except:
        raise requests.RequestException("ip-api.com could not be requested or did not provide a correct answer")

    if response.ok:
        response_json = response.json()
        if response_json["status"] == "success":
            del response_json["status"], response_json["query"]
            response_json["time"] = int(time())
            response_string = '-&%-'.join([str(value) for value in response_json.values()])
            
            crypted_response = SymmetricCrypto(ip_address).encrypt(response_string)
            hashed_ip = Hashing().hash(ip_address)

            ip_api_cache[hashed_ip] = crypted_response
            JSON.dump(ip_api_cache, IP_API_CACHE_PATH)

            return response_json
        
    raise requests.RequestException("ip-api.com could not be requested or did not provide a correct answer")
