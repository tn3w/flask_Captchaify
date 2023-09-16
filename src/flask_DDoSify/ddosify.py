import os
import re
import json
import random
import atexit
import secrets
import tarfile
import requests
import ipaddress
import pkg_resources
from time import time
from io import BytesIO
from zipfile import ZipFile
from base64 import b64encode
from bs4 import BeautifulSoup
from googletrans import Translator
from threading import Thread, Lock
from captcha.image import ImageCaptcha
from captcha.audio import AudioCaptcha
from urllib.parse import urlparse, quote
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from jinja2 import Environment, select_autoescape, Undefined
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, request, g, abort, send_file, make_response, redirect
from typing import Union, Optional

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

def get_client_ip() -> str:
    """
    Get the client IP in v4 or v6
    """
    def shorten_ipv6(ip_address):
        try:
            return str(ipaddress.IPv6Address(ip_address).compressed)
        except:
            return ip_address
    
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

class SilentUndefined(Undefined):
    def _fail_with_undefined_error(self, *args, **kwargs):
        return None

def render_template(file_name: str, **args) -> str:
    """
    Function to load an HTML file and perform optional string replacements.
    """

    if not os.path.isfile(file_name):
        raise FileNotFoundError("File '" + file_name + "' not found.")

    env = Environment(
        autoescape=select_autoescape(['html', 'xml']),
        undefined=SilentUndefined
    )
    
    with open(file_name, "r") as file:
        html = file.read()

    template = env.from_string(html)

    language = Language.get_language()

    args["language"] = language
    
    html = template.render(**args)

    html = Language.translate_page(html, "en", language)

    html = re.sub(r'<!--(.*?)-->', '', html, flags=re.DOTALL)
    html = re.sub(r'\s+', ' ', html)

    script_pattern = r'<script\b[^>]*>(.*?)<\/script>'
    def minimize_script(match):
        script_content = match.group(1)
        script_content = re.sub(r'\s+', ' ', script_content)
        return f'<script>{script_content}</script>'
    html = re.sub(script_pattern, minimize_script, html, flags=re.DOTALL | re.IGNORECASE)

    style_pattern = r'<style\b[^>]*>(.*?)<\/style>'
    def minimize_style(match):
        style_content = match.group(1)
        style_content = re.sub(r'\s+', ' ', style_content)
        return f'<style>{style_content}</style>'
    html = re.sub(style_pattern, minimize_style, html, flags=re.DOTALL | re.IGNORECASE)

    return html

file_locks = dict()

class JSON:

    def load(file_name: str) -> Union[dict, list]:
        """
        Function to load a JSON file securely.

        :param file_name: The JSON file you want to load
        """
        if not os.path.isfile(file_name):
            raise FileNotFoundError("File '" + file_name + "' does not exist.")
        
        if file_name not in file_locks:
            file_locks[file_name] = Lock()

        with file_locks[file_name]:
            with open(file_name, "r") as file:
                data = json.load(file)
            return data
        
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
            file_locks[file_name] = Lock()

        with file_locks[file_name]:
            with open(file_name, "w") as file:
                json.dump(data, file)

DATA_DIR = pkg_resources.resource_filename('flask_DDoSify', 'data')
TRANSLATIONS_PATH = os.path.join(DATA_DIR, "translations.json")
IP_API_CACHE_PATH = os.path.join(DATA_DIR, "ipapi-cache.json")
TEMPLATE_DIR = pkg_resources.resource_filename('flask_DDoSify', 'templates')
CRAWLER_USER_AGENTS = ["Googlebot", "bingbot", "Yahoo! Slurp", "YandexBot", "Baiduspider", "DuckDuckGo-Favicons-Bot", "AhrefsBot", "SemrushBot", "MJ12bot", "BLEXBot", "SeznamBot", "Exabot", "AhrefsBot", "archive.org_bot", "Applebot", "spbot", "Genieo", "linkdexbot", "Lipperhey Link Explorer", "SISTRIX Crawler", "MojeekBot", "CCBot", "Uptimebot", "XoviBot", "Neevabot", "SEOkicks-Robot", "meanpathbot", "MojeekBot", "RankActiveLinkBot", "CrawlomaticBot", "sentibot", "ExtLinksBot", "Superfeedr bot", "LinkfluenceBot", "Plerdybot", "Statbot", "Brainity", "Slurp", "Barkrowler", "RanksonicSiteAuditor", "rogerbot", "BomboraBot", "RankActiveLinkBot", "mail.ru", "AI Crawler", "Xenu Link Sleuth", "SEMrushBot", "Baiduspider-render", "coccocbot", "Sogou web spider", "proximic", "Yahoo Link Preview", "Cliqzbot", "woobot", "Barkrowler", "CodiBot", "libwww-perl", "Purebot", "Statbot", "iCjobs", "Cliqzbot", "SafeDNSBot", "AhrefsBot", "MetaURI API", "meanpathbot", "ADmantX Platform Semantic Analyzer", "CrawlomaticBot", "moget", "meanpathbot", "FPT-Aibot", "Domains Project", "SimpleCrawler", "YoudaoBot", "SafeDNSBot", "Slurp", "XoviBot", "Baiduspider", "FPT-Aibot", "SiteExplorer", "Lipperhey Link Explorer", "CrawlomaticBot", "SISTRIX Crawler", "SEMrushBot", "meanpathbot", "sentibot", "Dataprovider.com", "BLEXBot", "YoudaoBot", "Superfeedr bot", "moget", "Genieo", "sentibot", "AI Crawler", "Xenu Link Sleuth", "Barkrowler", "proximic", "Yahoo Link Preview", "Cliqzbot", "woobot", "Barkrowler"]
EMOJIS = JSON.load(os.path.join(DATA_DIR, "emojis.json"))
TEAEMOJIS = JSON.load(os.path.join(DATA_DIR, "teaemojis.json"))
LANGUAGES = JSON.load(os.path.join(DATA_DIR, "languages.json"))
LANGUAGES_CODE = [language["code"] for language in LANGUAGES]

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
    """
    Implementation of hashing with SHA256 and 50000 iterations
    """

    def __init__(self, salt: Optional[str] = None):
        """
        :param salt: The salt, makes the hashing process more secure
        """

        self.salt = salt

    def hash(self, plain_text: str, hash_length: int = 32) -> str:
        """
        Function to hash a plaintext

        :param plain_text: The text to be hashed
        :param hash_length: The length of the returned hashed value
        """

        plain_text = str(plain_text).encode('utf-8')

        salt = self.salt
        if salt is None:
            salt = secrets.token_bytes(32)
        else:
            if not isinstance(salt, bytes):
                try:
                    salt = bytes.fromhex(salt)
                except:
                    salt = salt.encode('utf-8')

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=hash_length,
            salt=salt,
            iterations=50000,
            backend=default_backend()
        )

        hashed_data = kdf.derive(plain_text)

        hash = urlsafe_b64encode(hashed_data).decode('utf-8') + "//" + salt.hex()
        return hash

    def compare(self, plain_text: str, hash: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plain_text: The text that was hashed
        :param hash: The hashed value
        """

        salt = self.salt
        if "//" in hash:
            hash, salt = hash.split("//")

        if salt is None:
            raise ValueError("Salt cannot be None if there is no salt in hash")
        
        salt = bytes.fromhex(salt)

        hash_length = len(urlsafe_b64decode(hash.encode('utf-8')))

        comparison_hash = Hashing(salt=salt).hash(plain_text, hash_length = hash_length).split("//")[0]

        return comparison_hash == hash
        
IP_INFO_KEYS = ['continent', 'continentCode', 'country', 'countryCode', 'region', 'regionName', 'city', 'district', 'zip', 'lat', 'lon', 'timezone', 'offset', 'currency', 'isp', 'org', 'as', 'asname', 'reverse', 'mobile', 'proxy', 'hosting', 'time']

def get_ip_info(ip_address: str) -> dict:
    """
    Function to query IP information with cache con ip-api.com
    """
    if os.path.isfile(IP_API_CACHE_PATH):
        ip_api_cache = JSON.load(IP_API_CACHE_PATH)
    else:
        ip_api_cache = {}

    for hashed_ip, crypted_data in ip_api_cache.items():
        comparison = Hashing().compare(ip_address, hashed_ip)
        if comparison:
            data = SymmetricCrypto(ip_address).decrypt(crypted_data)

            data_json = {}
            for i in range(22):
                data_json[IP_INFO_KEYS[i]] = data.split("-&%-")[i]

            if int(time()) - int(int(data_json["time"])) > 518400:
                del ip_api_cache[hashed_ip]
                break
            return data_json
        
    response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=66846719")
    response.raise_for_status()
    if response.ok:
        response_json = response.json()
        if response_json["status"] == "success":
            del response_json["status"], response_json["query"]
            response_json["time"] = time()
            response_string = '-&%-'.join([str(value) for value in response_json.values()])
            
            crypted_response = SymmetricCrypto(ip_address).encrypt(response_string)
            hashed_ip = Hashing().hash(ip_address)

            ip_api_cache[hashed_ip] = crypted_response
            JSON.dump(ip_api_cache, IP_API_CACHE_PATH)

            return response_json
    raise requests.RequestException("ip-api.com could not be requested or did not provide a correct answer")
    
class Language:

    def get_language():
        """
        Function to get the language of a user
        """

        if request.args.get("ddosify_language") in LANGUAGES_CODE:
            return request.args.get("ddosify_language")
        elif request.args.get("language") in LANGUAGES_CODE:
            return request.args.get("language")
        elif request.cookies.get("language") in LANGUAGES_CODE:
            return request.cookies.get("language")
        
        preferred_language = request.accept_languages.best_match(LANGUAGES_CODE)

        if preferred_language != None:
            return preferred_language
        
        return "en"

    @staticmethod
    def translate(text_to_translate: str, from_lang: str, to_lang: str) -> str:
        """
        Function to translate a text 'text_to_translate' from a language 'from_lang' to a language 'to_lang'
        """

        if from_lang == to_lang:
            return text_to_translate
        
        if os.path.isfile(TRANSLATIONS_PATH):
            translations = JSON.load(TRANSLATIONS_PATH)
        else:
            translations = []
        
        for translation in translations:
            if translation["text_to_translate"] == text_to_translate and translation["from_lang"] == from_lang and translation["to_lang"] == to_lang:
                return translation["translated_output"]
        
        translator = Translator()

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
    def translate_page(html: str, from_lang: str, to_lang: str) -> str:
        """
        Function to translate a page into the correct language
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
                    processed_content = Language.translate(content, from_lang, to_lang)
                    return f'{tag_open}{processed_content}{tag_close}'
                
                modified_text = re.sub(pattern, replace, text)
            else:
                modified_text = Language.translate(text, from_lang, to_lang)
            return modified_text
        
        tags = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'p', 'button'])
        for tag in tags:
            if 'ntr' not in tag.attrs:
                tag.string = translate_htmlified_text(tag)
        
        inputs = soup.find_all('input')
        for input_tag in inputs:
            if input_tag.has_attr('placeholder') and 'ntr' not in input_tag.attrs:
                input_tag['placeholder'] = Language.translate(input_tag['placeholder'], from_lang, to_lang)
        
        head_tag = soup.find('head')
        if head_tag:
            title_element = head_tag.find('title')
            if title_element:
                title_element.string = Language.translate(title_element.text, from_lang, to_lang)
        
        translated_html = str(soup).replace("&lt;", "<").replace("&gt;", ">")
        return translated_html

class Services:

    def need_update(ipsetpath: str):
        """
        Function to find out if an IPset needs an update
        """
        if not os.path.isfile(os.path.join(DATA_DIR, ipsetpath)):
            return True
        last_update_time = JSON.load(os.path.join(DATA_DIR, ipsetpath))["time"]
        if int(time()) - int(last_update_time) > 3600:
            return True
        return False
    
    def update_firehol_ip_set():
        """
        Function to update the IPset of FireHol
        """
        firehol_urls = [
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level2.netset",
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level3.netset",
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level4.netset"
        ]
        firehol_ips = {"time": str(int(time())), "ips": []}
        for firehol_url in firehol_urls:
            response = requests.get(firehol_url)
            if response.ok:
                ips = [line.strip().split('/')[0] for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
                firehol_ips["ips"].extend(ips)
            else:
                response.raise_for_status()
        firehol_ips["ips"] = list(set(firehol_ips["ips"]))
        JSON.dump(firehol_ips, os.path.join(DATA_DIR, "fireholipset.json"))
    
    def update_ip_deny_ip_set():
        """
        Function to update the IPset of IPDeny
        """
        ip_deny_urls = [
            "https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz",
            "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ipv6-all-zones.tar.gz"
        ]
        ip_deny_ips = {"time": str(int(time())), "ips": []}
        for ipdeny_url in ip_deny_urls:
            response = requests.get(ipdeny_url)
            if response.ok:
                tar_file = BytesIO(response.content)
                with tarfile.open(fileobj=tar_file, mode="r:gz") as tar:
                    members = tar.getmembers()
                    for member in members:
                        if member.isfile() and member.name.endswith('.zone'):
                            file_content = tar.extractfile(member).read().decode("utf-8")
                            ips = [line.strip().split('/')[0] for line in file_content.splitlines() if line.strip() and not line.startswith("#")]
                            ip_deny_ips["ips"].extend(ips)
            else:
                response.raise_for_status()
        ip_deny_ips["ips"] = list(set(ip_deny_ips["ips"]))
        JSON.dump(ip_deny_ips, os.path.join(DATA_DIR, "ipdenyipset.json"))
    
    def update_emerging_threats_ip_set():
        """
        Function to update the IPset of Emerging Threats
        """
        emerging_threats_url = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
        response = requests.get(emerging_threats_url)
        if response.ok:
            emerging_threats_ips = [line.strip().split('/')[0] for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
            emerging_threats_ips = list(set(emerging_threats_ips))
            JSON.dump({"time": str(int(time())), "ips": emerging_threats_ips}, os.path.join(DATA_DIR, "emergingthreatsipset.json"))
        else:
            response.raise_for_status()
    
    def update_my_ip_ms_ip_set():
        """
        Function to update the IPset of MyIP.ms
        """
        my_ip_ms_url = "https://myip.ms/files/blacklist/general/full_blacklist_database.zip"
        response = requests.get(my_ip_ms_url)
        if response.ok:
            with BytesIO(response.content) as zip_file:
                with ZipFile(zip_file, "r") as z:
                    with z.open("full_blacklist_database.txt", "r") as txt_file:
                        content = txt_file.read().decode('utf-8')
                        my_ip_ms_ips = [line.strip().split('/')[0].split('#')[0].replace('\t', '') for line in content.splitlines() if line.strip() and not line.startswith("#")]
                        my_ip_ms_ips = list(set(my_ip_ms_ips))
            JSON.dump({"time": str(int(time())), "ips": my_ip_ms_ips}, os.path.join(DATA_DIR, "myipmsipset.json"))
        else:
            response.raise_for_status()
    
    def update_tor_exit_nodes():
        tor_bulk_exit_list_url = "https://check.torproject.org/torbulkexitlist"
        response = requests.get(tor_bulk_exit_list_url)
        if response.ok:
            tor_exit_nodes_ip = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
            tor_exit_nodes_ip = list(set(tor_exit_nodes_ip))
            JSON.dump({"time": str(int(time())), "ips": tor_exit_nodes_ip}, os.path.join(DATA_DIR, "torexitnodes.json"))
        else:
            response.raise_for_status()
    
    def update_all_ipsets():
        if Services.need_update("fireholipset.json"):
            Services.update_firehol_ip_set()
        if Services.need_update("ipdenyipset.json"):
            Services.update_ip_deny_ip_set()
        if Services.need_update("emergingthreatsipset.json"):
            Services.update_emerging_threats_ip_set()
        if Services.need_update("myipmsipset.json"):
            Services.update_my_ip_ms_ip_set()
        if Services.need_update("torexitnodes.json"):
            Services.update_tor_exit_nodes()

Services.update_all_ipsets()

class DDoSify:
    """
    Shows the user/bot a captcha before the request first if the request comes from a dangerous IP
    Further function are: Rate Limits, Crawler Hints, Custom Templates, Rules for Specific Routes
    """

    def __init__ (
        self, app: Flask, actions: dict = {},
        hardness: dict = {}, rate_limits: dict = {}, template_dirs: dict = {},
        default_action: str = "captcha", default_hardness: int = 2, default_rate_limit: Optional[int] = 120, 
        default_max_rate_limit = 1200, default_template_dir: Optional[str] = None, verificationage: int = 3600,
        withoutcookies: bool = False, block_crawler: bool = True, crawler_hints: bool = True
        ):
        """
        Initialize the DDoSify object

        :param app: Your Flask App
        :param actions: Dict with actions for different routes like here: {"urlpath": "fight", "endpoint": "block"}, e.g. {"/": "block", "*/api/*": "let", "/login": "fight"} which blocks all suspicious traffic to "/", allows all traffic to /api/ routes e. e.g. "/api/cats" or "/dogs/api/" if they contain "/api/", and where to "/login" any traffic whether suspicious or not has to solve a captcha. (Default = {})
        :param hardness: Dict with hardness for different routes like here: {"urlpath": 1, "endpoint": 2}, e.g. {"/": 3, "*/api/*": 1, "/login": 3}. The urlpaths have the same structure as for actions. (Default = {})
        :param rate_limits: Dict with rate limit and max rate limit for different routes, the rate limit variable indicates how many requests an ip can make per minute, the max rate limit variable specifies the maximum number of requests that can come from all Ips like here: {"urlpath": (180, 1800), "endpoint": (130, 1300)}, e.g. {"/": (120, 1200), "*/api/*": (180, 1800), "/login": (60, 600)}. The urlpaths have the same structure as for actions. (Default = {})
        :param template_dirs: Dict with template folder for different routes like here: {"urlpath": "/path/to/template/dir", "endpoint": "/path/to/template/dir2"}, e.g. {"/": "/path/to/template/dir", "*/api/*": "/path/to/myapi/template/dir", "/login": "/path/to/login/template/dir"}. The urlpaths have the same structure as for actions. (Default = {})
        :param default_action: The default value of all pages if no special action is given in actions. (Default = "captcha")
        :param default_hardness: The default value of all pages if no special hardness is given in hardness. (Default = 2)
        :param default_rate_limit: How many requests an ip can make per minute, if nothing is given at rate_limits this value is used. If None, no rate limit is set. (Default = 120)
        :param default_max_rate_limit: How many requests all Ips can make per minute, if nothing is given at rate_limits this value is used. If None, no max rate limit is set. (Default = 1200)
        :param default_template_dir: The default value of all pages if no special template_dir is given in template_dirs. (Default = None)
        :param verificationage: How long the captcha verification is valid, in seconds (Default = 3600 [1 hour])
        :param withoutcookies: If True, no cookie is created after the captcha is fulfilled, but only an Arg is appended to the URL (Default = False)
        :param block_crawler: If True, known crawlers based on their user agent will also need to solve a captcha (Default = False)
        :param crawler_hints: If True, crawlers will cache a page with no content only with meta content of the real web page that is already in the cache.
        """

        if app is None:
            raise ValueError("The Flask app cannot be None")

        if not isinstance(actions, dict):
            actions = dict()
        
        if not isinstance(hardness, dict):
            hardness = dict()
        
        if not isinstance(rate_limits, dict):
            rate_limits = {}
        
        if not isinstance(template_dirs, dict):
            template_dirs = dict()
        
        if not default_action in ["let", "block", "fight", "captcha"]:
            default_action = "captcha"
        
        if not default_hardness in [1, 2, 3]:
            default_hardness = 2

        if not isinstance(default_rate_limit, int) and not default_rate_limit is None:
            default_rate_limit = 120
        
        if not isinstance(default_max_rate_limit, int) and not default_max_rate_limit is None:
            default_max_rate_limit = 1200
        
        if default_template_dir is None:
            default_template_dir = TEMPLATE_DIR

        if not isinstance(verificationage, int):
            verificationage = 3600
        
        if not isinstance(withoutcookies, bool):
            withoutcookies = False
        
        if not isinstance(block_crawler, bool):
            block_crawler = True
        
        if not isinstance(crawler_hints, bool):
            crawler_hints = True
        
        self.app = app

        self.actions = actions
        self.hardness = hardness
        self.rate_limits = rate_limits
        self.template_dirs = template_dirs

        self.default_action = default_action
        self.default_hardness = default_hardness
        self.default_rate_limit = default_rate_limit
        self.default_max_rate_limit = default_max_rate_limit
        self.default_template_dir = default_template_dir

        self.verificationage = verificationage
        self.withoutcookies = withoutcookies
        self.block_crawler = block_crawler
        self.crawler_hints = crawler_hints

        self.CAPTCHA_SECRET = generate_random_string(512)

        RATE_LIMIT_PATH = os.path.join(DATA_DIR, generate_random_string(10, with_punctuation=False) + "_rate-limit.json")
        while os.path.isfile(RATE_LIMIT_PATH):
            RATE_LIMIT_PATH = os.path.join(DATA_DIR, generate_random_string(10, with_punctuation=False) + "_rate-limit.json")
        self.RATE_LIMIT_PATH = RATE_LIMIT_PATH

        STOP_FORUM_SPAM_PATH = os.path.join(DATA_DIR, generate_random_string(10, with_punctuation=False) + "_sfs-cache.json")
        while os.path.isfile(STOP_FORUM_SPAM_PATH):
            STOP_FORUM_SPAM_PATH = os.path.join(DATA_DIR, generate_random_string(10, with_punctuation=False) + "_sfs-cache.json")
        self.STOP_FORUM_SPAM_PATH = STOP_FORUM_SPAM_PATH

        FAILED_CAPTCHA_PATH = os.path.join(DATA_DIR, generate_random_string(10, with_punctuation=False) + "_failed-captchas.json")
        while os.path.isfile(FAILED_CAPTCHA_PATH):
            FAILED_CAPTCHA_PATH = os.path.join(DATA_DIR, generate_random_string(10, with_punctuation=False) + "_failed-captchas.json")
        self.FAILED_CAPTCHA_PATH = FAILED_CAPTCHA_PATH

        CAPTCHA_SOLVED_PATH = os.path.join(DATA_DIR, generate_random_string(10, with_punctuation=False) + "_captcha-solved.json")
        while os.path.isfile(CAPTCHA_SOLVED_PATH):
            CAPTCHA_SOLVED_PATH = os.path.join(DATA_DIR, generate_random_string(10, with_punctuation=False) + "_captcha-solved.json")
        self.CAPTCHA_SOLVED_PATH = CAPTCHA_SOLVED_PATH

        if self.crawler_hints:
            CRAWLER_HINTS_PATH = os.path.join(DATA_DIR, generate_random_string(10, with_punctuation=False) + "_ch-cache.json")
            while os.path.isfile(CRAWLER_HINTS_PATH):
                CRAWLER_HINTS_PATH = os.path.join(DATA_DIR, generate_random_string(10, with_punctuation=False) + "_ch-cache.json")
            self.CRAWLER_HINTS_PATH = CRAWLER_HINTS_PATH

        app.before_request(self._set_ip)
        app.before_request(self._rate_limit)
        app.before_request(self._change_language)
        app.before_request(self._fight_bots)

        app.after_request(self._add_rate_limit)
        if self.withoutcookies:
            app.after_request(self._add_args)
        else:
            app.after_request(self._set_cookies)

        if self.crawler_hints:
            app.after_request(self._crawler_hints)

        atexit.register(self._delete_files)
    
    @property
    def _preferences(self):
        def is_correct_route(path: str):
            url_path = urlparse(request.url).path
            url_endpoint = request.endpoint

            url = url_path
            if not "/" in path:
                url = url_endpoint

            if '*' in path:
                real_path = path.replace("*", "")
                if (path.startswith("*") and path.endswith("*") and real_path in url) or \
                    (path.startswith("*") and url.endswith(real_path)) or \
                        (path.endswith("*") and url.startswith(real_path)):
                    return True
                first_part, second_part = path.split("*")[0], path.split("*")[1]

                if url.startswith(first_part) and url.endswith(second_part):
                    return True

            else:
                if path == url_endpoint:
                    return True
            
            return False

        current_url = {
            "action": self.default_action,
            "hardness": self.default_hardness,
            "rate_limit": self.default_rate_limit,
            "max_rate_limit": self.default_max_rate_limit,
            "template_dir": self.default_template_dir
        }

        preferences = [
            {"name": "action", "list": self.actions}, 
            {"name": "hardness", "list": self.hardness}, 
            {"name": "rate_limits", "list": self.rate_limits}, 
            {"name": "template_dir", "list": self.template_dirs}
        ]

        for preference in preferences:
            if len(preference["list"]) == 0:
                continue
            for path, path_preference in preference.items():
                if is_correct_route(path):
                    if preference["name"] != "rate_limits":
                        current_url[preference["name"]] = path_preference
                    else:
                        current_url["rate_limit"], current_url["max_rate_limit"] = path_preference
        
        return current_url
    
    def _correct_template(self, template_type: str, **args):
        if not template_type in ["captcha", "block", "rate_limited"]:
            raise Exception("'" + template_type + "' is not a Template Type.")
        
        template_dir = self._preferences["template_dir"]

        page_path = None

        for file in os.listdir(template_dir):
            if file.startswith(template_type):
                page_path = os.path.join(template_dir, file)
                break
        
        if page_path is None:
            return abort(404)
    
        page_ext = page_path.split('.')[-1]
        
        if page_ext == "html":
            html = render_template(page_path, **args)
            return html
        elif page_ext == "json":
            with open(page_path, "r") as file:
                return JSON.load(file)
        elif page_ext in ["txt", "xml"]:
            with open(page_path, "r") as file:
                return file.read()
        else:
            return send_file(page_path)
    
    def _delete_files(self):
        files = [self.RATE_LIMIT_PATH, self.STOP_FORUM_SPAM_PATH, self.FAILED_CAPTCHA_PATH, self.CAPTCHA_SOLVED_PATH]
        if self.crawler_hints:
            files.append(self.CRAWLER_HINTS_PATH)
        for file in files:
            try:
                os.remove(file)
            except:
                pass
        
    def _set_ip(self):
        g.ddosify_page = False
        g.is_crawler = False
        client_ip = get_client_ip()
        client_user_agent = request.user_agent.string
        if client_ip is None or client_user_agent is None:
            g.ddosify_page = True
            emoji = random.choice(EMOJIS)
            return self._correct_template("block", emoji = emoji)
        g.client_ip = client_ip
        g.client_user_agent = client_user_agent
        g.ddosify_captcha = None
    
    def _rate_limit(self):
        if os.path.isfile(self.RATE_LIMIT_PATH):
            rate_limited_ips = JSON.load(self.RATE_LIMIT_PATH)
        else:
            rate_limited_ips = {}

        preferences = self._preferences

        rate_limit = preferences["rate_limit"]
        max_rate_limit = preferences["max_rate_limit"]
        
        request_count = 0
        ip_request_count = 0

        for hashed_ip, ip_timestamps in rate_limited_ips.items():
            count = 0
            for request_time in ip_timestamps:
                if not int(time()) - int(request_time) > 60:
                    count += 1
            comparison = Hashing().compare(g.client_ip, hashed_ip)
            if comparison:
                ip_request_count += count
            request_count += count

        if (ip_request_count >= rate_limit and not rate_limit == 0) or \
            (request_count >= max_rate_limit and not max_rate_limit == 0):
            g.ddosify_page = True
            emoji = random.choice(TEAEMOJIS)
            return self._correct_template("rate_limited", emoji = emoji), 418
    
    def _change_language(self):
        if request.args.get("ddosify_changelanguage") == "1":
            languages = LANGUAGES

            search = None
            if not request.args.get("ddosify_search") is None:
                searchlanguages = []

                for lang in languages:
                    if request.args.get("ddosify_search").lower() in lang["name"].lower():
                        searchlanguages.append(lang)

                languages = searchlanguages
                search = request.args.get("ddosify_search")

            template_dir = self._preferences["template_dir"]

            for file in os.listdir(template_dir):
                if file.startswith("change_language"):
                    g.ddosify_page = True
                    return render_template(os.path.join(template_dir, file), search=search, languages=languages)
                
    def _fight_bots(self):
        url_path = urlparse(request.url).path

        def add_failed_captcha():
            if os.path.isfile(self.FAILED_CAPTCHA_PATH):
                seenips = JSON.load(self.FAILED_CAPTCHA_PATH)
            else:
                seenips = {}

            is_found = False

            for hashed_ip, ip_records in seenips.items():
                comparison = Hashing().compare(g.client_ip, hashed_ip)
                if comparison:
                    is_found = True

                    records_length = 0
                    for record in ip_records:
                        if not int(time()) - int(record) > 7200:
                            records_length += 1
                    records_length += 1

                    ip_records.append(str(int(time())))
                    seenips[hashed_ip] = ip_records

                    JSON.dump(seenips, self.FAILED_CAPTCHA_PATH)

            if not is_found:
                hashed_client_ip = Hashing().hash(g.client_ip)
                seenips[hashed_client_ip] = [str(int(time()))]

                JSON.dump(seenips, self.FAILED_CAPTCHA_PATH)
        
        def show_captcha(error: bool = False):
            captcha_token = Hashing().hash(url_path) + "-//-" + str(int(time())) + "-//-" + str(hardness) + "-//-" +\
                Hashing().hash(g.client_ip) + "-//-" + Hashing().hash(g.client_user_agent) + "-//-"

            string_length = (5 if hardness == 1 else 8 if hardness == 2 else 9) + random.choice([1, 1, 2, 3])
            
            image_captcha_code = generate_random_string(string_length, with_punctuation=False)

            if string_length > 6:
                image_captcha_code = image_captcha_code.upper()
            
            image_captcha = ImageCaptcha(width=320, height=120, fonts=[
                os.path.join(DATA_DIR, "Comic_Sans_MS.ttf"),
                os.path.join(DATA_DIR, "DroidSansMono.ttf"),
                os.path.join(DATA_DIR, "Helvetica.ttf")
            ])

            captcha_image = image_captcha.generate(image_captcha_code)

            captcha_image_data = b64encode(captcha_image.getvalue()).decode('utf-8')
            captcha_image_data = "data:image/png;base64," + captcha_image_data

            captcha_token += image_captcha_code

            captcha_audio_data = None

            if hardness == 3:
                int_length = 8 + random.choice([1, 2, 3, 4, 5, 6])

                audio_captcha_code = generate_random_string(int_length, with_punctuation=False, with_letters=False)
                audio_captcha = AudioCaptcha()
                captcha_audio = audio_captcha.generate(audio_captcha_code)

                captcha_audio_data = b64encode(captcha_audio).decode('utf-8')
                captcha_audio_data = "data:audio/wav;base64," + captcha_audio_data

                captcha_token += "-//-" + audio_captcha_code
            
            coded_captcha_token = SymmetricCrypto(self.CAPTCHA_SECRET).encrypt(captcha_token)

            error = "That was not right, try again!" if error else None

            return self._correct_template("captcha", error = error, textCaptcha=captcha_image_data, audioCaptcha = captcha_audio_data, captchatoken=coded_captcha_token)

        action = self._preferences["action"]
        hardness = self._preferences["hardness"]

        if action == "let":
            return

        is_crawler = False
        for crawlername in CRAWLER_USER_AGENTS:
            if crawlername.lower() in g.client_user_agent.lower():
                is_crawler = True
        
        g.is_crawler = is_crawler
        
        t = Thread(target=Services.update_all_ipsets)
        t.start()

        FIREHOL_IPS = JSON.load(os.path.join(DATA_DIR, "fireholipset.json"))["ips"]
        IPDENY_IPS = JSON.load(os.path.join(DATA_DIR, "ipdenyipset.json"))["ips"]
        EMERGINGTHREATS_IPS = JSON.load(os.path.join(DATA_DIR, "emergingthreatsipset.json"))["ips"]
        MYIPMS_IPS = JSON.load(os.path.join(DATA_DIR, "myipmsipset.json"))["ips"]
        TOREXITNODES_IPS = JSON.load(os.path.join(DATA_DIR, "torexitnodes.json"))["ips"]

        criteria = [
            g.client_ip in FIREHOL_IPS,
            g.client_ip in IPDENY_IPS,
            g.client_ip in EMERGINGTHREATS_IPS,
            g.client_ip in MYIPMS_IPS,
            g.client_ip in TOREXITNODES_IPS,
            is_crawler and self.block_crawler,
            action == "fight"
        ]

        if not any(criteria):
            if os.path.isfile(self.STOP_FORUM_SPAM_PATH):
                stopforumspamcache = JSON.load(self.STOP_FORUM_SPAM_PATH)
            else:
                stopforumspamcache = {}

            found = False
            
            for hashed_ip, ip_content in stopforumspamcache.items():
                comparison = Hashing().compare(g.client_ip, hashed_ip)
                if comparison:
                    found = True
                    
                    if ip_content["spammer"] and not int(time()) - int(ip_content["time"]) > 604800:
                        criteria.append(True)
                    break

            if not found:
                response = requests.get(f"https://api.stopforumspam.org/api?ip={g.client_ip}&json")
                if response.ok:
                    try:
                        content = response.json()
                    except:
                        criteria.append(True)
                    else:
                        spammer = False
                        if content["ip"]["appears"] > 0:
                            spammer = True
                            criteria.append(True)

                        hashed_client_ip = Hashing().hash(g.client_ip)

                        stopforumspamcache[hashed_client_ip] = {"spammer": spammer, "time": int(time())}
                        
                        JSON.dump(stopforumspamcache, self.STOP_FORUM_SPAM_PATH)
                else:
                    criteria.append(True)
        
        if not any(criteria):
            return
        
        if action == "block":
            g.ddosify_page = True
            emoji = random.choice(EMOJIS)
            return self._correct_template("block", emoji = emoji)
        
        if os.path.isfile(self.FAILED_CAPTCHA_PATH):
            failed_captchas = JSON.load(self.FAILED_CAPTCHA_PATH)
        else:
            failed_captchas = {}

        for hashed_ip, ip_records in failed_captchas.items():
            comparison = Hashing().compare(g.client_ip, hashed_ip)
            if comparison:
                records_length = 0
                for record in ip_records:
                    if not int(time()) - int(record) > 14400:
                        records_length += 1
                if (action == "fight" or hardness == 3) and records_length > 2 or records_length > 3:
                    g.ddosify_page = True
                    emoji = random.choice(EMOJIS)
                    return self._correct_template("block", emoji = emoji)
        
        is_failed_captcha = False
        
        if request.args.get("captchasolved") == "1":
            text_captcha = request.args.get("textCaptcha")
            audio_captcha = request.args.get("audioCaptcha")
            captcha_token = request.args.get("captchatoken")

            if not None in [text_captcha, captcha_token]:
                try:
                    captcha_token_decrypted = SymmetricCrypto(self.CAPTCHA_SECRET).decrypt(captcha_token)
                except:
                    pass
                else:
                    ct = captcha_token_decrypted.split('-//-')

                    ct_path, ct_time, ct_hardness, ct_ip, ct_useragent, ct_text = ct[0], ct[1], int(ct[2]), ct[3], ct[4], ct[5]

                    is_failing = False

                    if ct_hardness == 3:
                        ct_audio = ct[6]

                        if hardness == 3:
                            if audio_captcha is None:
                                is_failing = True
                            else:
                                if str(audio_captcha) != str(ct_audio):
                                    is_failing = True
                        else:
                            if not audio_captcha is None:
                                if not str(audio_captcha) != str(ct_audio):
                                    ct_hardness = hardness
                            else:
                                ct_hardness = hardness
                    
                    if not is_failing:
                        if not hardness < ct_hardness:
                            comparison_path = Hashing().compare(url_path, ct_path)
                            comparison_ip = Hashing().compare(g.client_ip, ct_ip)
                            comparison_user_agent = Hashing().compare(g.client_user_agent, ct_useragent)

                            if not comparison_path or \
                                int(time()) - int(ct_time) > 180 or \
                                    (not comparison_ip and not comparison_user_agent) or \
                                        str(text_captcha) != str(ct_text):
                                is_failed_captcha = True

                            else:
                                id = generate_random_string(16, with_punctuation=False)
                                token = generate_random_string(40)

                                if os.path.isfile(self.CAPTCHA_SOLVED_PATH):
                                    captcha_solved = JSON.load(self.CAPTCHA_SOLVED_PATH)
                                else:
                                    captcha_solved = {}
                                
                                while any([Hashing().compare(id, hashed_id) for hashed_id, _ in captcha_solved.items()]):
                                    id = generate_random_string(with_punctuation=False)

                                symcrypto = SymmetricCrypto(self.CAPTCHA_SECRET)

                                data = {
                                    "time": int(time()),
                                    "ip": symcrypto.encrypt(g.client_ip),
                                    "user_agent": symcrypto.encrypt(g.client_user_agent),
                                    "hardness": symcrypto.encrypt(str(ct_hardness))
                                }

                                if os.path.isfile(self.CAPTCHA_SOLVED_PATH):
                                    captcha_solved = JSON.load(self.CAPTCHA_SOLVED_PATH)
                                else:
                                    captcha_solved = {}
                                
                                captcha_solved[Hashing().hash(id)] = data

                                JSON.dump(captcha_solved, self.CAPTCHA_SOLVED_PATH)

                                g.ddosify_captcha = id+token

                                if self.withoutcookies:
                                    return redirect(request.url.replace("http://", request.scheme + "://")\
                                        .replace("?textCaptcha=" + str(request.args.get("textCaptcha")), "").replace("&textCaptcha=" + str(request.args.get("textCaptcha")), "")\
                                        .replace("?audioCaptcha=" + str(request.args.get("audioCaptcha")), "").replace("&audioCaptcha=" + str(request.args.get("audioCaptcha")), "")\
                                        .replace("?captchatoken=" + str(request.args.get("captchatoken")), "").replace("&captchatoken=" + str(request.args.get("captchatoken")), "")\
                                        .replace("?captchasolved=1", "").replace("&captchasolved=1", "") + "?captcha=" + quote(g.ddosify_captcha))
                                return
                        else:
                            is_failed_captcha = True
                    else:
                        is_failed_captcha = True
            else:
                is_failed_captcha = True
        
        captcha_token = None
        if not request.args.get("captcha") is None:
            captcha_token = request.args.get("captcha")
        elif not request.cookies.get("captcha") is None:
            captcha_token = request.cookies.get("captcha")

        if captcha_token is None:
            g.ddosify_page = True
            if is_failed_captcha:
                add_failed_captcha()
            return show_captcha(error=is_failed_captcha)
        
        if len(captcha_token) != 56:
            g.ddosify_page = True
            if is_failed_captcha:
                add_failed_captcha()
            return show_captcha(error=is_failed_captcha)
            
        id, token = captcha_token[:16], captcha_token[16:]

        if os.path.isfile(self.CAPTCHA_SOLVED_PATH):
            captcha_solved = JSON.load(self.CAPTCHA_SOLVED_PATH)
        else:
            captcha_solved = {}
       
        for hashed_id, ip_data in captcha_solved.items():
            comparison = Hashing().compare(id, hashed_id)
            if comparison:
                crypto = SymmetricCrypto(self.CAPTCHA_SECRET)
                datatime = ip_data["time"]
                try:
                    ip = crypto.decrypt(ip_data["ip"])
                    useragent = crypto.decrypt(ip_data["user_agent"])
                    captcha_hardness = int(crypto.decrypt(ip_data["hardness"]))
                except:
                    pass
                else:
                    if not int(time()) - int(datatime) > self.verificationage and hardness >= captcha_hardness:
                        if ip == g.client_ip and useragent == g.client_user_agent:
                            return
                break
        
        g.ddosify_page = True

        if is_failed_captcha:
            add_failed_captcha()

        return show_captcha(error=is_failed_captcha)

    def _add_rate_limit(self, response):
        rate_limit = self._preferences["rate_limit"]

        if not rate_limit == 0:
            if os.path.isfile(self.RATE_LIMIT_PATH):
                rate_limited_ips = JSON.load(self.RATE_LIMIT_PATH)
            else:
                rate_limited_ips = {}

            found = False
            for hashed_ip, ip_timestamps in rate_limited_ips.items():
                comparison = Hashing().compare(g.client_ip, hashed_ip)
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
                hashed_client_ip = Hashing().hash(g.client_ip, 16)
                rate_limited_ips[hashed_client_ip] = [str(int(time()))]
            
            JSON.dump(rate_limited_ips, self.RATE_LIMIT_PATH)
        
        return response

    def _set_cookies(self, response):
        response = make_response(response)
        if not g.ddosify_captcha is None:
            response.set_cookie("captcha", g.ddosify_captcha, max_age = self.verificationage, httponly = True, secure = self.app.config.get("HTTPS"))
        if request.args.get("ddosify_language") in LANGUAGES_CODE:
            response.set_cookie("language", request.args.get("ddosify_language"), max_age = 60*60*24*30*12*3, httponly = True, secure = self.app.config.get("HTTPS"))
        elif request.args.get("language") in LANGUAGES_CODE:
            response.set_cookie("language", request.args.get("language"), max_age = 60*60*24*30*12*3, httponly = True, secure = self.app.config.get("HTTPS"))
        elif request.cookies.get("language") in LANGUAGES_CODE:
            response.set_cookie("language", request.cookies.get("language"), max_age = 60*60*24*30*12*3, httponly = True, secure = self.app.config.get("HTTPS"))
        return response

    def _add_args(self, response):
        if response.content_type == "text/html; charset=utf-8":
            args = {}
            if not g.ddosify_captcha is None:
                args["captcha"] = g.ddosify_captcha
            elif not request.args.get("captcha") is None:
                args["captcha"] = request.args.get("captcha")

            if request.args.get("ddosify_language") in LANGUAGES_CODE:
                args["language"] = request.args.get("ddosify_language")
            elif request.args.get("language") in LANGUAGES_CODE:
                args["language"] = request.args.get("language")
            elif request.cookies.get("language") in LANGUAGES_CODE:
                args["language"] = request.cookies.get("language")

            html = response.data

            soup = BeautifulSoup(html, 'html.parser')

            for anchor in soup.find_all('a'):
                try:
                    if not anchor['href']:
                        continue
                except:
                    continue

                if "://" in anchor['href']:
                    anchor_host = urlparse(anchor['href']).netloc
                    if not anchor_host == request.host:
                        continue
                elif not anchor['href'].startswith("/") and \
                    not anchor['href'].startswith("#") and \
                        not anchor['href'].startswith("?") and \
                            not anchor['href'].startswith("&"):
                    continue

                for arg, content in args.items():
                    special_character = "?"
                    if "?" in anchor["href"]:
                        special_character = "&"
                    anchor['href'] = anchor['href'] + special_character + arg + "=" + quote(content)
                
            for form in soup.find_all("form"):
                added_input = ""
                for arg, content in args.items():
                    added_input += f'<input type="hidden" name="{arg}" value="{content}">'
                
                form_button = form.find('button')
                if form_button:
                    form_button.insert_before(added_input)
                else:
                    form.append(added_input)
                
                if "action" in form.attrs:
                    for arg, content in args.items():
                        special_character = "?"
                        if "?" in form['action']:
                            special_character = "&"
                        form['action'] = form['action'] + special_character + arg + "=" + quote(content)
        
            response.data = str(soup).replace("&lt;", "<").replace("&gt;", ">")
        
        return response
    
    def _crawler_hints(self, response):
        if not response.content_type == "text/html; charset=utf-8":
            return response
        
        if os.path.isfile(self.CRAWLER_HINTS_PATH):
            crawler_hints = JSON.load(self.CRAWLER_HINTS_PATH)
        else:
            crawler_hints = {}

        path = request.path
        
        found = None

        copy_crawler_hints = crawler_hints.copy()

        for hashed_path, path_data in crawler_hints.items():
            comparison = Hashing().compare(path, hashed_path)
            if comparison:
                try:
                    decrypted_path_data = json.loads(SymmetricCrypto(path).decrypt(path_data))
                except:
                    del copy_crawler_hints[hashed_path]
                else:
                    if not int(time()) - int(decrypted_path_data["time"]) > 7200:
                        found = hashed_path
                    else:
                        del copy_crawler_hints[hashed_path]
                break

        symmetric_crypto = SymmetricCrypto(path)
        
        if found is None and not g.ddosify_page:
            html = response.data
            soup = BeautifulSoup(html, 'html.parser')

            title_tag = soup.title
            title = title_tag.string if title_tag else None
            og_tags = ''.join(str(og_tag) for og_tag in soup.find_all('meta', attrs={'property': 'og'}))

            hashed_path = Hashing().hash(path)

            copy_crawler_hints[hashed_path] = {
                "time": int(time),
                "title": symmetric_crypto.encrypt(str(title)),
                "og_tags": symmetric_crypto.encrypt(og_tags)
            }

        if copy_crawler_hints != crawler_hints:
            JSON.dump(copy_crawler_hints, self.CRAWLER_HINTS_PATH)
        
        if not found is None and g.ddosify_page:
            if g.is_crawler:
                html = response.data
                soup = BeautifulSoup(html, 'html.parser')

                title = symmetric_crypto.decrypt(crawler_hints[found]["title"])
                if not title == "None":
                    soup.title.string = title

                og_soup = BeautifulSoup(symmetric_crypto.decrypt(crawler_hints[found]["og_tags"]), 'html.parser')

                for tag in og_soup.find_all('meta'):
                    soup.head.append(tag)
                
                response = make_response(response)
        
        return response
