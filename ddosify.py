import os
import string
import secrets
import requests
import json
from io import BytesIO
import tarfile
from zipfile import ZipFile
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode, b64encode
from flask import request, send_file, make_response, redirect
from googletrans import Translator # Version: 3.1.0a0
from bs4 import BeautifulSoup
import ipaddress
from jinja2 import Environment, FileSystemLoader, select_autoescape, Undefined
from urllib.parse import urlparse, quote
from time import time
from captcha.image import ImageCaptcha
from captcha.audio import AudioCaptcha

CURRENT_DIR = os.getcwd()
DATA_DIR = os.path.join(CURRENT_DIR, "data")

# Paths for cache files, and IP log files
SEENIPS_PATH = os.path.join(DATA_DIR, "seenips.json")
CAPTCHASOLVED_PATH = os.path.join(DATA_DIR, "captchasolved.json")
ONETIME_PATH = os.path.join(DATA_DIR, "onetime.json")
STOPFORUMSPAM_PATH = os.path.join(DATA_DIR, "stopforumspamcache.json")

def generate_random_string(length: int, with_punctuation: bool = True, with_letters: bool = True):
    """
    Generates a random string of the specified length with optional character types

    :param length: The desired length of the random string
    :param with_punctuation: Specifies whether special characters should be included in the string (default: True)
    :param with_letters: Specifies whether letters should be included in the string (default: True)

    :return: A random string of the given length with the given characters.
    """

    # Define a basic string of digits (0-9)
    characters = string.digits
    
    # Add special characters if the option 'with_punctuation' is activated.
    if with_punctuation:
        characters += string.punctuation

    # Add letters if the option 'with_letters' is activated.
    if with_letters:
        characters += string.ascii_letters

    # Create a random string of the desired length by dragging characters from the 'characters' string and returns it
    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string

# The captcha secret is used to check the captcha of the user
if not os.path.isfile(os.path.join(DATA_DIR, "captchasecret.txt")):
    CAPTCHASECRET = generate_random_string(1024)
    with open(os.path.join(DATA_DIR, "captchasecret.txt"), "w") as file:
        file.write(CAPTCHASECRET)
else:
    with open(os.path.join(DATA_DIR, "captchasecret.txt"), "r") as file:
        CAPTCHASECRET = file.read()

# Check if the "fireholipset.json" file is not present
if not os.path.isfile(os.path.join(DATA_DIR, "fireholipset.json")):
    # List of URLs to the FireHOL IP lists
    firehol_urls = [
        "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
        "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level2.netset",
        "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level3.netset",
        "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level4.netset"
    ]

    # Empty list for the collected IP addresses
    firehol_ips = []

    # Loop to retrieve and process the IP lists.
    for firehol_url in firehol_urls:
        response = requests.get(firehol_url)
        if response.ok:
            # Extract the IP addresses from the response and add them to the list
            ips = [line.strip().split('/')[0] for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
            firehol_ips.extend(ips)
        else:
            response.raise_for_status()

    # Remove duplicates from the list of collected IP addresses
    FIREHOL_IPS = list(set(firehol_ips))
    
    # Open the JSON file in write mode and save the collected IP addresses
    with open(os.path.join(DATA_DIR, "fireholipset.json"), "w") as file:
        json.dump(FIREHOL_IPS, file)
else:
    with open(os.path.join(DATA_DIR, "fireholipset.json"), "r") as file:
        FIREHOL_IPS = json.load(file)

# Check if the "ipdenyipset.json" file is not present
if not os.path.isfile(os.path.join(DATA_DIR, "ipdenyipset.json")):
    # List of URLs to the IP deny IP lists (for IPv4 and IPv6).
    ipdeny_urls = [
        "https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz",
        "https://www.ipdeny.com/ipv6/ipaddresses/blocks/ipv6-all-zones.tar.gz"
    ]

    # Empty list for the collected IP addresses
    ipdeny_ips = []

    # Loop to retrieve and process the IP lists.
    for ipdeny_url in ipdeny_urls:
        response = requests.get(ipdeny_url)
        if response.ok:
            # Load the TAR-GZ file and extract its contents
            tar_file = BytesIO(response.content)
            with tarfile.open(fileobj=tar_file, mode="r:gz") as tar:
                members = tar.getmembers()
                for member in members:
                    # Check if the member is a file and has the extension ".zone".
                    if member.isfile() and member.name.endswith('.zone'):
                        # Read the contents of the file, decode it as UTF-8 and extract the IP addresses
                        file_content = tar.extractfile(member).read().decode("utf-8")
                        ips = [line.strip().split('/')[0] for line in file_content.splitlines() if line.strip() and not line.startswith("#")]
                        ipdeny_ips.extend(ips)
        else:
            response.raise_for_status()
    
    # Remove duplicates from the list of collected IP addresses
    IPDENY_IPS = list(set(ipdeny_ips))
    
    # Open the JSON file in write mode and save the collected IP addresses
    with open(os.path.join(DATA_DIR, "ipdenyipset.json"), "w") as file:
        json.dump(IPDENY_IPS, file)
else:
    with open(os.path.join(DATA_DIR, "ipdenyipset.json"), "r") as file:
        IPDENY_IPS = json.load(file)

# Check if the "emergingthreatsipset.json" file is not present
if not os.path.isfile(os.path.join(DATA_DIR, "emergingthreatsipset.json")):
    # URL to get the list of IP's
    emergingthreats_url = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    
    # Request the list of IP's
    response = requests.get(emergingthreats_url)
    
    # Check if the request was successful
    if response.ok:
        # Extract the IP addresses from the response and remove duplicates
        emergingthreats_ips = [line.strip().split('/')[0] for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
        EMERGINGTHREATS_IPS = list(set(emergingthreats_ips))
        
        # Open the JSON file in write mode and save the list of Ips.
        with open(os.path.join(DATA_DIR, "emergingthreatsipset.json"), "w") as file:
            json.dump(EMERGINGTHREATS_IPS, file)
    else:
        response.raise_for_status()
else:
    with open(os.path.join(DATA_DIR, "emergingthreatsipset.json"), "r") as file:
        EMERGINGTHREATS_IPS = json.load(file)

# Check if the "myipmsipset.json" file is not present
if not os.path.isfile(os.path.join(DATA_DIR, "myipmsipset.json")):
    # URL to get the list of IP's
    myipms_url = "https://myip.ms/files/blacklist/general/full_blacklist_database.zip"
    
    # Request the zip file
    response = requests.get(myipms_url)
    
    # Check if the request was successful
    if response.ok:
        with BytesIO(response.content) as zip_file:
            # Load the ZIP file and extract its contents
            with ZipFile(zip_file, "r") as z:
                with z.open("full_blacklist_database.txt", "r") as txt_file:
                    content = txt_file.read().decode('utf-8')
                    myipms_ips = [line.strip().split('/')[0].split('#')[0].replace('\t', '') for line in content.splitlines() if line.strip() and not line.startswith("#")]
                    MYIPMS_IPS = list(set(myipms_ips))
        
        # Open the JSON file in write mode and save the list of Ips.
        with open(os.path.join(DATA_DIR, "myipmsipset.json"), "w") as file:
            json.dump(MYIPMS_IPS, file)
    else:
        response.raise_for_status()
else:
    with open(os.path.join(DATA_DIR, "myipmsipset.json"), "r") as file:
        MYIPMS_IPS = json.load(file)

# Check if the "torexitnodes.json" file is not present
if not os.path.isfile(os.path.join(DATA_DIR, "torexitnodes.json")):
    # URL to get the list of Tor exit nodes
    torbulkexitlist_url = "https://check.torproject.org/torbulkexitlist"
    
    # Request the list of Tor exit nodes
    response = requests.get(torbulkexitlist_url)
    
    # Check if the request was successful
    if response.ok:
        # Extract the IP addresses from the response and remove duplicates
        torexitnodes_ip = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith("#")]
        TOREXITNODES_IPS = list(set(torexitnodes_ip))
        
        # Open the JSON file in write mode and save the list of Tor exit nodes.
        with open(os.path.join(DATA_DIR, "torexitnodes.json"), "w") as file:
            json.dump(TOREXITNODES_IPS, file)
    else:
        response.raise_for_status()
else:
    with open(os.path.join(DATA_DIR, "torexitnodes.json"), "r") as file:
        TOREXITNODES_IPS = json.load(file)

class SymmetricCrypto:
    """
    Implementation of secure symmetric encryption with AES
    """

    def __init__(self, password: Optional[str] = None, salt_length: int = 32):
        """
        Initialize the SymmetricCrypto object with password and salt_length

        :param password: A secure encryption password, should be at least 32 characters long
        :param salt_length: The length of the salt, should be at least 16
        """

        # If the password is not given, a secure random password is created
        if password is None:
            password = secrets.token_urlsafe(64)

        self.password = password.encode()
        self.salt_length = salt_length

    def generate_key_and_salt(self) -> Tuple[bytes, bytes]:
        """
        Generates Key with KDF and a secure random Salt

        :return: The encryption key generated with PBKDF2HMAC and the randomly generated salt used to generate the key has a length of self.salt_length as Tuple
        """

        # Generate a random salt
        salt = secrets.token_bytes(self.salt_length)

        # Use PBKDF2HMAC to derive the encryption key
        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)
        
        return key, salt

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypts a text with the password and a salt

        :param plaintext: The text to be encrypted, as a string
        
        :return: The text encrypted with the password and a randomly generated salt and iv
        """

        # Generate a random salt and encryption key
        key, salt = self.generate_key_and_salt()

        # Generate a random IV (Initialization Vector)
        iv = secrets.token_bytes(16)

        # Use AES in CBC mode to encrypt the plaintext
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Combine salt, iv, and ciphertext, and return as a URL-safe Base64 encoded string
        return urlsafe_b64encode(salt + iv + ciphertext).decode()

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts a text with the password and a salt

        :param ciphertext: The encrypted text, must have been encrypted with the password, as a string
        
        :return: The actual text
        """

        # Decode the URL-safe Base64 encoded ciphertext
        ciphertext = urlsafe_b64decode(ciphertext.encode())

        # Extract salt, iv, and ciphertext from the combined data
        salt, iv, ciphertext = ciphertext[:self.salt_length], ciphertext[self.salt_length:self.salt_length + 16], ciphertext[self.salt_length + 16:]

        # Derive the encryption key using the password and salt
        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        # Decrypt the ciphertext
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

        # Return the decrypted plaintext
        return plaintext.decode()

class Hashing:
    """
    Implementation of secure hashing with SHA256 and 200000 iterations
    """

    def __init__(self, salt: Optional[str] = None):
        """
        Initialize the Hashing object with salt

        :param salt: The salt, makes the hashing process more secure (Optional)
        """

        self.salt = salt

    def hash(self, plaintext: str, hash_length: int = 32) -> str:
        """
        Function to hash a plaintext

        :param plaintext: The text to be hashed
        :param hash_length: The length of the returned hashed value

        :return: The hashed plaintext
        """

        # Convert plaintext to bytes
        plaintext = str(plaintext).encode('utf-8')

        # Set the salt, which is generated randomly if it is not defined and otherwise made into bytes if it is string
        salt = self.salt
        if salt is None:
            salt = secrets.token_bytes(32)
        else:
            if not isinstance(salt, bytes):
                try:
                    salt = bytes.fromhex(salt)
                except:
                    salt = salt.encode('utf-8')

        # Create a PBKDF2 instance using the SHA-256 hash algorithm
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=hash_length,
            salt=salt,
            iterations=200000,
            backend=default_backend()
        )

        # Calculate the bytes hash
        hashed_data = kdf.derive(plaintext)

        # Make/Return the bytes hash with base64 and add the salt after it
        hash = urlsafe_b64encode(hashed_data).decode('utf-8') + "//" + salt.hex()
        return hash

    def compare(self, plaintext: str, hash: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plaintext: The text that was hashed
        :param hash: The hashed value

        :return: The result of the comparison as bool

        :raises ValueError: If salt is None and there is no salt in the provided hash
        """

        # The salt is defined
        salt = self.salt
        if "//" in hash:
            hash, salt = hash.split("//")

        if salt is None:
            raise ValueError("Salt cannot be None if there is no salt in hash")

        # Get the hash length by making the hash from a base64 encoded string into a bytes object and measuring the length from it
        hash_length = len(urlsafe_b64decode(hash.encode('utf-8')))

        # A second hash of the plaintext is generated 
        comparisonhash = Hashing(salt=bytes.fromhex(salt)).hash(plaintext, hash_length = hash_length).split("//")[0]

        # The two hashes are compared and the result is returned
        return comparisonhash == hash

# Loading the languages lists to use them in the Languages class
with open(os.path.join(DATA_DIR, "languages.json"), "r") as file:
    LANGUAGES = json.load(file)

LANGUAGE_LIST = [language["code"] for language in LANGUAGES]

class Language:
    """
    Implementation of various methods that have something to do with languages
    """

    @staticmethod
    def speak(default: str = "en") -> str:
        """
        Function to get the language of a user

        :param default: The language to be returned if no language can be found

        :return: The language preferred by the user
        """
        
        # Get the preferred language of the user
        preferred_language = request.accept_languages.best_match(LANGUAGE_LIST)

        # If the preferred language is not None
        if preferred_language != None:
            return preferred_language
        
        # Return the default language if no user languages are provided
        return default

    @staticmethod
    def translate(text_to_translate: str, from_lang: str, to_lang: str) -> str:
        """
        Function to translate a text 'text_to_translate' from a language 'from_lang' to a language 'to_lang'

        :param text_to_translate: The text in language 'from_lang' to be translated into language 'to_lang'
        :param from_lang: The language of the 'text_to_translate', can also be 'auto'
        :param to_lang: The language in which the text should be translated 'text_to_translate'

        :return: The translated text

        :raises Exception: If no translation could be made
        """

        # If both languages match, the text is simply returned
        if from_lang == to_lang:
            return text_to_translate

        # Specify the file path to the translation file
        translations_file = os.path.join(DATA_DIR, "translations.json")
        
        if os.path.isfile(translations_file):
            # If the file exists, load the translations from the file
            with open(translations_file, "r") as file:
                translations = json.load(file)
        else:
            # If the file does not exist, initialize the translations as an empty list
            translations = []
        
        # Check if the translation is already available in the cache
        for translation in translations:
            if translation["text_to_translate"] == text_to_translate and translation["from_lang"] == from_lang and translation["to_lang"] == to_lang:
                return translation["output"]
        
        # Perform the translation using the Translator class
        translator = Translator()
        try:
            output = translator.translate(text_to_translate, src=from_lang, dest=to_lang).text
        except:
            raise Exception("The text could not be translated")
            
        try:
            output = output.encode('latin-1').decode('unicode_escape')
        except:
            pass
        
        # Cache the translation in the translations file
        translation = {
            "text_to_translate": text_to_translate, 
            "from_lang": from_lang,
            "to_lang": to_lang, 
            "output": output
        }
        translations.append(translation)
        
        with open(translations_file, "w") as file:
            json.dump(translations, file)

        # In some languages, it looks better if the first character is large
        if to_lang in ["de", "en", "es", "fr", "pt", "it"]:
            output = output[0].upper() + output[1:]
            
        return output

    @staticmethod
    def translate_page(html: str, from_lang: str, to_lang: str) -> str:
        """
        Function to translate a page into the correct language

        :param html: The untranslated page in 'from_lang'
        :param from_lang: The language of the HTML page given with 'html'
        :param to_lang: The language into which the HTML web page should be translated

        :return: The translated HTML page

        > Note: function can give a bs4 error if the html page is poorly implemented as well as errors in the individual for loops e.g. for missing attributes.
        """
        
        soup = BeautifulSoup(html, 'html.parser')
        
        # Translate headers
        headers = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
        for header in headers:
            if 'ntr' not in header.attrs and not header.text == None:
                header.string = Language.translate(header.text, from_lang, to_lang)
        
        # Translate links
        links = soup.find_all('a')
        for link in links:
            if 'ntr' not in link.attrs and not link.text == None:
                link.string = Language.translate(link.text, from_lang, to_lang)
        
        # Translate paragraphs
        paragraphs = soup.find_all('p')
        for paragraph in paragraphs:
            # Ignore tags that have the 'ntr' attribute or do not contain text nodes
            if 'ntr' in paragraph.attrs or paragraph.text == None:
                continue

            # Ignores all p tags that have either an image or a link in them and not the attr linkintext
            if (len(paragraph.find_all('img')) > 0 or len(paragraph.find_all('a')) > 0) and not 'linkintext' in paragraph.attrs:
                continue
            else:
                # Translates the paragraph
                paragraph.string = Language.translate(paragraph.text, from_lang, to_lang)
        
        # Translate buttons
        buttons = soup.find_all('button')
        for button in buttons:
            if 'ntr' not in button.attrs and not button.text == None:
                button.string = Language.translate(button.text, from_lang, to_lang)
        
        # Translate input placeholders
        inputs = soup.find_all('input')
        for input_tag in inputs:
            if input_tag.has_attr('placeholder') and 'ntr' not in input_tag.attrs:
                input_tag['placeholder'] = Language.translate(input_tag['placeholder'], from_lang, to_lang)
        
        # Get the translated HTML
        translated_html = str(soup)
        return translated_html

def shorten_ipv6(ip_address: str) -> str:
    """
    Function to shorten an IPv6 IP address.

    :param ip_address: Any IP address, can also be IPv4.
    
    :return: The shortened IPv6 IP address or the given ip_address if it's not a valid IPv6.
    """
    try:
        return str(ipaddress.IPv6Address(ip_address).compressed)
    except: # ipaddress.AddressValueError
        return ip_address

def get_client_ip() -> str:
    """
    Function to get the IP address of a user.

    :return: The IP with which the client has requested the server.
    
    :raises Exception: If no IP address was found.
    """
    headers_to_check = [
        'X-Forwarded-For',
        'X-Real-Ip',
        'CF-Connecting-IP',
        'True-Client-Ip',
    ]

    for header in headers_to_check:
        if header in request.headers:
            # Extract the client's IP from the header and handle multiple IPs (e.g., proxy or VPN).
            client_ip = request.headers[header]
            client_ip = client_ip.split(',')[0].strip()
            client_ip = shorten_ipv6(client_ip) # Shortens Ipv6 to compare it better with block lists
            return client_ip

    # If no headers contain the IP, fallback to using request.remote_addr
    client_ip = request.remote_addr
    client_ip = shorten_ipv6(client_ip)  # Shortens Ipv6 to compare it better with block lists

    if client_ip is None:
        raise Exception("Failed to get the user's IP address.")

    return client_ip

CRAWLER_USER_AGENTS = ["Googlebot", "bingbot", "Yahoo! Slurp", "YandexBot", "Baiduspider", "DuckDuckGo-Favicons-Bot", "AhrefsBot", "SemrushBot", "MJ12bot", "BLEXBot", "SeznamBot", "Exabot", "AhrefsBot", "archive.org_bot", "Applebot", "spbot", "Genieo", "linkdexbot", "Lipperhey Link Explorer", "SISTRIX Crawler", "MojeekBot", "CCBot", "Uptimebot", "XoviBot", "Neevabot", "SEOkicks-Robot", "meanpathbot", "MojeekBot", "RankActiveLinkBot", "CrawlomaticBot", "sentibot", "ExtLinksBot", "Superfeedr bot", "LinkfluenceBot", "Plerdybot", "Statbot", "Brainity", "Slurp", "Barkrowler", "RanksonicSiteAuditor", "rogerbot", "BomboraBot", "RankActiveLinkBot", "mail.ru", "AI Crawler", "Xenu Link Sleuth", "SEMrushBot", "Baiduspider-render", "coccocbot", "Sogou web spider", "proximic", "Yahoo Link Preview", "Cliqzbot", "woobot", "Barkrowler", "CodiBot", "libwww-perl", "Purebot", "Statbot", "iCjobs", "Cliqzbot", "SafeDNSBot", "AhrefsBot", "MetaURI API", "meanpathbot", "ADmantX Platform Semantic Analyzer", "CrawlomaticBot", "moget", "meanpathbot", "FPT-Aibot", "Domains Project", "SimpleCrawler", "YoudaoBot", "SafeDNSBot", "Slurp", "XoviBot", "Baiduspider", "FPT-Aibot", "SiteExplorer", "Lipperhey Link Explorer", "CrawlomaticBot", "SISTRIX Crawler", "SEMrushBot", "meanpathbot", "sentibot", "Dataprovider.com", "BLEXBot", "YoudaoBot", "Superfeedr bot", "moget", "Genieo", "sentibot", "AI Crawler", "Xenu Link Sleuth", "Barkrowler", "proximic", "Yahoo Link Preview", "Cliqzbot", "woobot", "Barkrowler"]

with open(os.path.join(DATA_DIR, "emojis.json"), "r") as file:
    EMOJIS = json.load(file)

# So that no Jinja Undefined errors come
class SilentUndefined(Undefined):
    def _fail_with_undefined_error(self, *args, **kwargs):
        return None

def render_template(filepath: str, **args) -> str:
    """
    Function to load an HTML file and perform optional string replacements.

    :params filepath: The path of the file
    :params args: Jinja2 Args

    :returns html: The HTML page

    :raises FileNotFoundError: If the file does not exist
    """
    
    # Raise a FileNotFoundError if the file does not exist
    if not os.path.isfile(filepath):
        raise FileNotFoundError(filepath)
        
    # Configuration of the Jinja2 environment
    env = Environment(
        loader=FileSystemLoader(os.path.dirname(filepath)),
        autoescape=select_autoescape(['html', 'xml']),
        undefined=SilentUndefined
    )
    
    # Load the template file
    template = env.get_template(os.path.basename(filepath))
    
    # Render the template with the passed variables
    html = template.render(**args)
    
    # Return the HTML content
    return html

class DDoSify:
    """
    Shows the user/bot a captcha before the request first if the request comes from a dangerous IP
    """

    def __init__ (
        self, app, actions: dict = {}, template_dir: Optional[str] = None, hardness: int = 2,
        botfightmode: bool = False, verificationage: int = 3600, withoutcookies: bool = False, 
        block_crawler: bool = False
    ):

        """
        Initialize the DDoSify object

        :param app: Your Flask App
        :param actions: Define what happens on certain routes/endpoint in the following format: {"/my_special_route": "let"}, where the first is the route and the action follows. The following actions are available: 'block' (blocks all requests that look suspicious, without captcha), 'let' (lets all requests through without action), 'hard' (sets the hardness for this route to 3), 'normal' (sets the hardness for this route to 2), 'easy' (sets the hardness for this route to 1). The action for each page can also be set as a tuple like here {"/my_special_route": ("/path/to/my/custom/template": 'action')}, where you can set a different captcha/block template for each page.
        :param template_dir: Where the program should use templates, the file should have "captcha.html" and "block.html" for the respective actions.
        :param hardness: The hardness of the captcha, value 1-3, where 3 is high (default = 2)
        :param botfightmode: If true a captcha is displayed to all connections, True or False (default = False)
        :param verificationage: How long the captcha verification is valid, in seconds (default = 3600 [1 hour])
        :param withoutcookies: If True, no cookie is created after the captcha is fulfilled, but only an Arg is appended to the URL
        :param block_crawler: If True, known crawlers based on their user agent will also need to solve a captcha

        :raises ValueError: If the flask app is None
        """
        
        if app is None:
            raise ValueError("The Flask app cannot be None")

        if not isinstance(actions, dict):
            actions = {}

        if not hardness in [1,2,3]:
            hardness = 2

        if not isinstance(botfightmode, bool):
            botfightmode = False

        if not isinstance(verificationage, int):
            verificationage = 3600

        if not isinstance(withoutcookies, bool):
            withoutcookies = False

        if not isinstance(block_crawler, bool):
            block_crawler = False

        self.app = app
        self.actions = actions
        self.template_dir = template_dir
        self.hardness = hardness
        self.botfightmode = botfightmode
        self.verificationage = verificationage
        self.withoutcookies = withoutcookies
        self.block_crawler = block_crawler

        app.before_request(self.show_ddosify)
        # app.after_request(self.add_args) FIXME: Function so that all links on a HTML response page get the captcha args

    def show_ddosify(self):
        """
        This function displays different DDoSify pages e.g. Captcha and Block if needed
        """

        # Get the URL path of the current request
        urlpath = urlparse(request.url).path

        # Set a default action based on the hardness level of the application
        action = "hard" if self.hardness == 3 else "normal" if self.hardness == 2 else "easy"

        # Initialize the template variable to None
        template = None

        # Find a matching action for the current request
        if not self.actions.get(urlpath) is None or not self.actions.get(request.endpoint) == None:
            if not self.actions.get(urlpath) is None:
                _action = self.actions.get(urlpath)
            else:
                _action = self.actions.get(request.endpoint)

            # If the action is defined as a tuple (template, action), extract the template and action
            if isinstance(_action, tuple):
                _template, _action = _action
                # Check if the specified template file or directory exists
                if os.path.isfile(_template) or os.path.isdir(_template):
                    # If the template exists, set the template variable to its value
                    template = _template

            # Check if the action is a valid one among ["block", "let", "hard", "normal", "easy"]
            if _action in ["block", "let", "hard", "normal", "easy"]:
                # Set the action variable to the defined action for the current request
                action = _action

        elif not self.actions.get("all") == None:
            _action = self.actions.get("all")
            
            # If the action is defined as a tuple (template, action), extract the template and action
            if isinstance(_action, tuple):
                _template, _action = _action
                # Check if the specified template file or directory exists
                if os.path.isfile(_template) or os.path.isdir(_template):
                    # If the template exists, set the template variable to its value
                    template = _template

            # Check if the action is a valid one among ["block", "let", "hard", "normal", "easy"]
            if _action in ["block", "let", "hard", "normal", "easy"]:
                # Set the action variable to the defined action for the current request
                action = _action

        # If the action is 'let' nothing more is executed
        if action == "let":
            return

        # When an error occurs a captcha is displayed
        error = False

        try:
            # Get the client's IP address
            clientip = get_client_ip()
        except:
            # If an error occurs while fetching the client's IP, set the error flag
            error = True
            clientip = None

        try:
            # Get the client's user agent string from the request
            clientuseragent = request.user_agent.string
        except:
            # If an error occurs while fetching the user agent, set the error flag
            error = True
            clientuseragent = None
        else:
            # If the user agent is None, set the error flag
            if clientuseragent == None:
                error = True

        # Check if the client's user agent indicates that it is a web crawler
        is_crawler = False
        if not error:
            for crawlername in CRAWLER_USER_AGENTS:
                if crawlername.lower() in clientuseragent.lower():
                    is_crawler = True

        # Define the criteria for blocking or showing captcha
        criteria = [
            error,
            clientip in FIREHOL_IPS,
            clientip in IPDENY_IPS,
            clientip in EMERGINGTHREATS_IPS,
            clientip in MYIPMS_IPS,
            clientip in TOREXITNODES_IPS,
            self.botfightmode,
            is_crawler and self.block_crawler,
        ]

        # If none of the criteria is True and the action is not "let" proceed to check StopForumSpam API
        if not any(criteria):
            # Check if the StopForumSpam cache file exists and load its content
            if os.path.isfile(STOPFORUMSPAM_PATH):
                with open(STOPFORUMSPAM_PATH, "r") as file:
                    stopforumspamcache = json.load(file)
            else:
                # If the cache file doesn't exist, create an empty dictionary
                stopforumspamcache = {}

            # Variable indicating whether the IP was found in the cache
            found = False
            
            # Check if the client's IP exists in the StopForumSpam cache
            for hashed_ip, content in stopforumspamcache.items():
                comparison = Hashing().compare(clientip, hashed_ip)
                if comparison:
                    # The IP was found in the cache
                    found = True
                    
                    # If the IP is flagged as a spammer and the time since last check is less than 7 days (604800 seconds), block the request
                    if content["spammer"] and not int(time()) - int(content["time"]) > 604800:
                        criteria.append(True)
                    break

            if not found:
                # If the IP is not found in the cache, make a request to the StopForumSpam API
                response = requests.get(f"https://api.stopforumspam.org/api?ip={clientip}&json")
                if response.ok:
                    try:
                        content = response.json()
                    except:
                        # If an error occurs while parsing the API response, block the request
                        criteria.append(True)
                    else:
                        spammer = False
                        # Check if the IP appears in the StopForumSpam database and set the spammer flag accordingly
                        if content["ip"]["appears"] > 0:
                            spammer = True
                            criteria.append(True)

                        # The clientip is hashed and stored like this
                        hashed_clientip = Hashing().hash(clientip)

                        # Update the StopForumSpam cache with the result and current timestamp
                        stopforumspamcache[hashed_clientip] = {"spammer": spammer, "time": int(time())}
                        with open(STOPFORUMSPAM_PATH, "w") as file:
                            json.dump(stopforumspamcache, file)
                else:
                    # If the request to the API fails, block the request
                    criteria.append(True) 

        # If any of the criteria are met and the action is not "let," block or show captcha
        if any(criteria):
            if action == "block":
                # Show block page
                return self.show_block(template)

            # Load the list of previously seen IPs from a file
            if os.path.isfile(SEENIPS_PATH):
                with open(SEENIPS_PATH, "r") as file:
                    seenips = json.load(file)
            else:
                seenips = []

            if not clientip is None:
                # Compare the client's IP with the seen IPs to determine if it's a repeated visit
                for hashed_ip, records in seenips:
                    # Compare the client's IP with each hashed IP stored in the "seenips" list
                    comparison = Hashing().compare(clientip, hashed_ip)
                    if comparison:
                        records_length = 0
                        for record in records:
                            # Calculate the number of records (visits) within the last 4 hours (14400 seconds)
                            if not int(time()) - int(record) > 14400:
                                records_length += 1
                        # If the application is in botfightmode or the action is set to "hard," apply stricter rules
                        if self.botfightmode or action == "hard":
                            if records_length > 1:
                                # If there have been more than one record (two or more false captchas) within the last 2 hours, block the request
                                return self.show_block(template)
                        else:
                             # If the application is not in botfightmode and the action is not "hard," apply normal rules
                            if records_length > 2:
                                # If there have been more than two records (three or more false captchas) within the last 2 hours, block the request
                                return self.show_block(template)
                        break

            # If the request method is POST
            if request.method == "POST":
                text_captcha = request.form.get("textCaptcha")
                audio_captcha = request.form.get("audioCaptcha")
                captcha_token = request.form.get("captchatoken")

                # If the text_captcha and the captcha_token is None, a captcha has to be solved
                if None in [text_captcha, captcha_token]:
                    return self.show_captcha(template, error=True)

                # Decrypt the captcha token and split it at "-//-"
                captcha_token_decrypted = SymmetricCrypto(CAPTCHASECRET).decrypt(captcha_token)
                ct = captcha_token_decrypted.split('-//-')

                # Get the url path, time, hardness, ip, user agent and text captcha code from the captcha token
                ct_path, ct_time, ct_hardness, ct_ip, ct_useragent, ct_text = ct[0], ct[1], int(ct[2]), ct[3], ct[4], ct[5]

                # The hardness of the current web page is set
                this_page_hardness = (3 if action == "hard" else 2 if action == "normal" else 1 if action == "easy" else self.hardness)

                # If the difficulty of the solved captcha is high (= audio captcha is also required)
                if ct_hardness == 3:

                    # The audio captcha token is obtained from the captcha token
                    ct_audio = ct[6]

                    # If the current page also has one of three, getting the audio captcha wrong will cause the check to fail.
                    if this_page_hardness == 3:
                        if audio_captcha is None:
                            return self.show_captcha(template, error=True)
                        else:
                            if str(audio_captcha) != str(ct_audio):
                                return self.show_captcha(template, error=True)
                    else:
                        # If the current page does not actually require an audio captcha, the check is still accepted if the audio captcha is incorrect, but the solved difficulty is set to the hardness of the current page
                        if not audio_captcha is None:
                            if not str(audio_captcha) != str(ct_audio):
                                ct_hardness = this_page_hardness
                        else:
                            ct_hardness = this_page_hardness

                # However, if the required hardness of this side is greater than that of the solved captcha, then the check is invalid
                if this_page_hardness < ct_hardness:
                    return self.show_captcha(template, error=True)
                
                # Compare the hash of the data contained in the captcha token with the data of the current web page
                comparison_path = Hashing().compare(urlpath, ct_path)
                comparison_ip = Hashing().compare(clientip, ct_ip)
                comparison_useragent = Hashing().compare(clientuseragent, ct_useragent)

                # If the comparisons are not valid or the time has expired, or the text_captcha is not valid, then a captcha is displayed
                if not comparison_path or int(time()) - int(ct_time) > 180 or (not comparison_ip and not comparison_useragent) or str(text_captcha) != str(ct_text):
                    return self.show_captcha(template, error=True)
                
                # Get the scheme
                scheme = request.headers.get('X-Forwarded-Proto', 'http' if request.environ.get('HTTPS') is None else 'https')
                
                # Create the response
                if not self.withoutcookies:
                    resp = make_response(redirect(request.url.replace("http", scheme)))
                else:
                    resp_url = request.url.replace("http", scheme)
                
                # If the Ip or the user agent does not match, no captcha solve token is created, but only a one-time token intended for one-time verification
                if comparison_ip and comparison_useragent:
                    # Generate ID and token
                    id = generate_random_string(16, with_punctuation=False)
                    token = generate_random_string(40)

                    # If captcha have already been solved, they will be loaded
                    if os.path.isfile(CAPTCHASOLVED_PATH):
                        with open(CAPTCHASOLVED_PATH, "r") as file:
                            captchasolved = json.load(file)
                    else:
                        captchasolved = {}
                    
                    # It is checked whether the generated ID already exists
                    while any([Hashing().compare(id, hashed_id) for hashed_id, _ in captchasolved.items()]):
                        id = generate_random_string(with_punctuation=False)

                    # Initialise the SymetricCrypto Class with the generated encryption token
                    symcrypto = SymmetricCrypto(token)

                    # Creates a data model with the ID and encrypted data
                    data = {
                        "time": time(),
                        "ip": symcrypto.encrypt(clientip),
                        "user_agent": symcrypto.encrypt(clientuseragent),
                        "hardness": symcrypto.encrypt(str(ct_hardness))
                    }

                    # The solved captchas are loaded again
                    if os.path.isfile(CAPTCHASOLVED_PATH):
                        with open(CAPTCHASOLVED_PATH, "r") as file:
                            captchasolved = json.load(file)
                    else:
                        captchasolved = {}
                    
                    # The generated ID is added to the dict
                    captchasolved[Hashing().hash(id)] = data

                    # The solved captchas are saved
                    with open(CAPTCHASOLVED_PATH, "w") as file:
                        json.dump(captchasolved, file)

                    # Add the created data to the response
                    if self.withoutcookies:
                        resp_url += "?" if not "?" in request.url else "&" + "captcha=" + quote(id+token)
                    else:
                        resp.set_cookie("captcha", id+token, max_age=self.verificationage)
                
                # Create and Hashe a One Time Token
                onetime_token = generate_random_string(30)
                hashed_onetime_token = Hashing().hash(onetime_token, 64) + "-//-" + str(int(time()))

                # If there are already One Time Tokens stored, load them, otherwise []
                if os.path.isfile(ONETIME_PATH):
                    with open(ONETIME_PATH, "r") as file:
                        onetime = json.load(file)
                else:
                    onetime = []
                
                # Add the hash of the created token to the list
                onetime.append(hashed_onetime_token)

                # Save the One Time Tokens
                with open(ONETIME_PATH, "w") as file:
                    json.dump(onetime, file)
                
                # Add the created One Time Token to the response
                if self.withoutcookies:
                    resp_url += "&captcha_onetime=" + quote(onetime)
                    resp = redirect(resp_url)
                else:
                    resp.set_cookie("captcha_onetime", onetime_token, max_age=60)

                return resp
            
            captcha_token = None
            if not request.args.get("captcha") is None:
                captcha_token = request.args.get("captcha")
            elif not request.cookies.get("captcha") is None:
                captcha_token = request.cookies.get("captcha")

            if captcha_token is None:
                # Show captcha challenge if no captcha token is found
                return self.show_captcha(template)

            # Validate the captcha token
            if len(captcha_token) != 56:
                return self.show_captcha(template)
                
            id, token = captcha_token[:16], captcha_token[16:]

            # Load the list of captcha verifications from a file
            with open(CAPTCHASOLVED_PATH, "r") as file:
                captchasolved = json.load(file)
            
            for hashed_id, data in captchasolved.items():
                # Compare the captcha ID with the stored IDs to find a match
                comparison = Hashing().compare(id, hashed_id)
                if comparison:
                    crypto = SymmetricCrypto(token)
                    datatime = data["time"]
                    try:
                        # Decrypt IP, user agent and hardness of solved captcha from the stored data
                        ip = crypto.decrypt(data["ip"])
                        useragent = crypto.decrypt(data["user_agent"])
                        hardness = int(crypto.decrypt(data["hardness"]))
                    except:
                        pass
                    else:
                        # If the captcha is still valid, check for botfightmode and match with client's IP and user agent
                        if not int(time()) - int(datatime) > self.verificationage and hardness >= self.hardness:
                            if not self.botfightmode and not action == "hard":
                                if ip == clientip or useragent == clientuseragent:
                                    return
                            else:
                                if ip == clientip and useragent == clientuseragent:
                                    return
                    break
                    
            # Show captcha challenge if no valid captcha verification is found
            return self.show_captcha(template)

    def show_block(self, template: Optional[str] = None):
        """
        This function generates a block page to be shown in case of blocking a request.
        
        :param template: Path to a custom template file or directory (Optional).
        
        :return: The content of the block page (HTML, JSON, TXT, or XML).

        :raises Exception: If the built-in template directory or the block.html in it does not exist
        """

        pagepath = None
        
        # Check if a custom template is provided and set the pagepath accordingly
        if not template is None:
            if os.path.isfile(template):
                # If the template is a file, use it as the pagepath
                pagepath = os.path.isfile(template)
            elif os.path.isdir(template):
                # If the template is a directory, find the block template file inside it
                for file in os.path.listdir(template):
                    filewithoutext = file.replace("." + file.split('.')[-1], "")
                    if filewithoutext.lower() == "block":
                        pagepath = os.path.join(template, file)
                    break

        # If no custom template is found, check for a default template
        if pagepath is None:
            template_dir = self.template_dir
            if not template_dir is None:
                for file in os.path.listdir(template_dir):
                    filewithoutext = file.replace("." + file.split('.')[-1], "")
                    if filewithoutext.lower() == "block":
                        pagepath = os.path.join(template_dir, file)
                    break
                if pagepath is None:
                    print("[INFO-DDoSify] The specified template_dir does not contain a block template, the built-in one is used.")

            # If still no template is found, use the built-in block template
            if pagepath is None:
                pagepath = os.path.join(os.path.join(CURRENT_DIR, "templates"), "block.html")
                if not os.path.isfile(pagepath):
                    raise Exception("The module does not seem to be installed correctly, either the built-in template_dir is missing or the block.html file in it.")

        # Determine the file extension of the template
        pageext = pagepath.split('.')[-1]
        
        if pageext == "html":
            # If the template is an HTML file, process and translate the page content

            # Get the language based on the user's preference
            language = Language.speak()

            # Render the HTML template, adding an emoji to it using a random choice from the emojis list
            page = render_template(pagepath, language = language, emoji = secrets.choice(EMOJIS))

            try:
                # Translate the page content from English to the user's preferred language
                translated_page = Language.translate_page(page, "en", language)
            except:
                # If translation fails, use the original page content
                translated_page = page

            return translated_page
            
        elif pageext == "json":
            # If the template is a JSON file, load and return its content
            with open(pagepath, "r") as file:
                return json.load(file)
                
        elif pageext in ["txt", "xml"]:
            # If the template is a TXT or XML file, read and return its content
            with open(pagepath, "r") as file:
                return file.read()
        
        else:
            # If the template file has an unsupported extension, serve it as a file download
            return send_file(pagepath)

    def show_captcha(self, template: Optional[str] = None, error: bool = False):
        """
        This function generates a captcha page for the user.
        
        :param template: Path to a custom template file or directory (Optional).
        :param error: If there is a need to show error notifications to the user.
        
        :return: The content of the captcha page (HTML, JSON, TXT, or XML).

        :raises Exception: If the built-in template directory or the captcha.html in it does not exist
        """

        # Get the URL path of the current request
        urlpath = urlparse(request.url).path

        # Set the hardness based on the normal hardness level of the application
        hardness = self.hardness

        # Find a matching action for the current request
        if not self.actions.get(urlpath) is None or not self.actions.get(request.endpoint) == None:
            if not self.actions.get(urlpath) is None:
                _action = self.actions.get(urlpath)
            else:
                _action = self.actions.get(request.endpoint)

            # If the action is defined as a tuple (template, action), extract the action
            if isinstance(_action, tuple):
                _, _action = _action

            # Check if the action is a valid one among ["block", "let", "hard", "normal", "easy"]
            if _action == "block":
                return self.show_block(template=template)
            elif _action == "let":
                return
            else:
                hardness = 3 if self.hardness == "hard" else 2 if self.hardness == "normal" else 1

        elif not self.actions.get("all") == None:
            _action = self.actions.get("all")

            # If the action is defined as a tuple (template, action), extract the action
            if isinstance(_action, tuple):
                _, _action = _action

            # Check if the action is a valid one among ["block", "let", "hard", "normal", "easy"]
            if _action == "block":
                return self.show_block(template=template)
            elif _action == "let":
                return
            else:
                hardness = 3 if self.hardness == "hard" else 2 if self.hardness == "normal" else 1

        pagepath = None
        
        # Check if a custom template is provided and set the pagepath accordingly
        if not template is None:
            if os.path.isfile(template):
                # If the template is a file, use it as the pagepath
                pagepath = os.path.isfile(template)
            elif os.path.isdir(template):
                # If the template is a directory, find the captcha template file inside it
                for file in os.path.listdir(template):
                    filewithoutext = file.replace("." + file.split('.')[-1], "")
                    if filewithoutext.lower() == "captcha":
                        pagepath = os.path.join(template, file)
                    break

        # If no custom template is found, check for a default template
        if pagepath is None:
            template_dir = self.template_dir
            if not template_dir is None:
                for file in os.path.listdir(template_dir):
                    filewithoutext = file.replace("." + file.split('.')[-1], "")
                    if filewithoutext.lower() == "captcha":
                        pagepath = os.path.join(template_dir, file)
                    break
                if pagepath is None:
                    print("[INFO-DDoSify] The specified template_dir does not contain a captcha template, the built-in one is used.")

            # If still no template is found, use the built-in captcha template
            if pagepath is None:
                pagepath = os.path.join(os.path.join(CURRENT_DIR, "templates"), "captcha.html")
                if not os.path.isfile(pagepath):
                    raise Exception("The module does not seem to be installed correctly, either the built-in template_dir is missing or the captcha.html file in it.")
        
        try:
            # Get the client's IP address
            clientip = get_client_ip()
        except:
            # If an error occurs while fetching the client's IP, set the error flag
            clientip = None

        try:
            # Get the client's user agent string from the request
            clientuseragent = request.user_agent.string
        except:
            clientuseragent = None
        
        if clientip is None and clientuseragent is None:
            return self.show_block(template)
    
        # Create basic data of the captcha_token
        captcha_token = Hashing().hash(urlpath) + "-//-" + str(int(time())) + "-//-" + str(hardness) + "-//-" + Hashing().hash(clientip) + "-//-" + Hashing().hash(clientuseragent) + "-//-"

        # Calculate the length of the random string based on the hardness level
        string_length = (5 if hardness == 1 else 8 if hardness == 2 else 9) + secrets.choice([1, 1, 2, 3])
        
        # Generate the random string
        image_captcha_code = generate_random_string(string_length, with_punctuation=False).replace("v", "V").replace("s", "S")

        # Change the captcha to uppercase letters only to make it not too difficult
        if string_length > 6:
            image_captcha_code = image_captcha_code.upper()

        # Create the ImageCaptcha instance with specified width, height, and fonts
        image_captcha = ImageCaptcha(width=320, height=120, fonts=[
            os.path.join(DATA_DIR, "Comic_Sans_MS.ttf"),
            os.path.join(DATA_DIR, "DroidSansMono.ttf"),
            os.path.join(DATA_DIR, "Helvetica.ttf")
        ])

        # Generate the captcha image
        captcha_image = image_captcha.generate(image_captcha_code)

        # Convert the captcha_image to base64-encoded string with "data:image/png;base64," prefix
        captcha_image_data = b64encode(captcha_image.getvalue()).decode('utf-8')
        captcha_image_data = "data:image/png;base64," + captcha_image_data

        captcha_token += image_captcha_code

        captcha_audio_data = None

        if hardness == 3:
            # Calculate the length of the random int code based on the hardness level
            int_length = 8 + secrets.choice([1, 2, 3, 4, 5, 6])

            # Generate the random int code
            audio_captcha_code = generate_random_string(int_length, with_punctuation=False, with_letters=False)

            # Create the AudioCaptcha instance
            audio_captcha = AudioCaptcha()

            # Generate the captcha audio
            captcha_audio = audio_captcha.generate(audio_captcha_code)

            # Convert the captcha_audio to base64-encoded string with "data:audio/wav;base64," prefix
            captcha_audio_data = b64encode(captcha_audio).decode('utf-8')
            captcha_audio_data = "data:audio/wav;base64," + captcha_audio_data

            captcha_token += "-//-" + audio_captcha_code
        
        coded_captcha_token = SymmetricCrypto(CAPTCHASECRET).encrypt(captcha_token)

        errormessage = None
        if error:
            errormessage = "That was not right, try again!"
            
        # Determine the file extension of the template
        pageext = pagepath.split('.')[-1]
        
        if pageext == "html":
            # Get the language based on the user's preference
            language = Language.speak()

            # Render the HTML template, adding an emoji to it using a random choice from the emojis list
            page = render_template(pagepath, language = language, errormessage = errormessage, textCaptcha=captcha_image_data, audioCaptcha = captcha_audio_data, captchatoken=coded_captcha_token)

            try:
                # Translate the page content from English to the user's preferred language
                translated_page = Language.translate_page(page, "en", language)
            except:
                # If translation fails, use the original page content
                translated_page = page

            return translated_page
            
        else:
            return send_file(pagepath)
