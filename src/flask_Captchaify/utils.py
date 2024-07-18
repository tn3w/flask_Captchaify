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
import time
import json
import gzip
import pickle
import random
import secrets
import traceback
import threading
import unicodedata
from typing import Union, Optional, Final
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, urljoin
from base64 import b64decode, b64encode
from werkzeug import Request
import cv2
import numpy as np


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Create the file test.env in the `src/flask_Captchaify` folder if you do
# not want to install the module with pip but want to import it from this
# folder, e.g. to display code changes directly.
if not os.path.exists(os.path.join(CURRENT_DIR, 'test.env')):
    import pkg_resources

def get_work_dir():
    """
    Determine the working directory for the application.

    :return: The working directory path.
    """

    if os.path.exists(os.path.join(CURRENT_DIR, 'test.env')):
        return CURRENT_DIR

    return pkg_resources.resource_filename('flask_Captchaify', '')

WORK_DIR: Final[str] = get_work_dir()
DATA_DIR: Final[str] = os.path.join(WORK_DIR, 'data')

if not os.path.isdir(DATA_DIR):
    os.makedirs(DATA_DIR, exist_ok = True)

ASSETS_DIR: Final[str] = os.path.join(WORK_DIR, 'assets')
TEMPLATE_DIR: Final[str] = os.path.join(WORK_DIR, 'templates')
DATASETS_DIR: Final[str] = os.path.join(WORK_DIR, 'datasets')

ASSETS_DIR: Final[str] = os.path.join(WORK_DIR, 'assets')
LOG_FILE: Final[str] = os.path.join(CURRENT_DIR, 'log.txt')

USER_AGENTS: Final[list] = [
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
PERMISSION_MODES: Final[dict] = {
    'r': os.R_OK,
    'w': os.W_OK,
    'x': os.X_OK,
    'rw': os.R_OK | os.W_OK,
    'rx': os.R_OK | os.X_OK,
    'wx': os.W_OK | os.X_OK,
}

WRITE_EXECUTOR = ThreadPoolExecutor()


###########################
#### Generic functions ####
###########################


def remove_duplicates(origin_list: list) -> list:
    """
    Remove duplicates from a list.

    :param origin_list: The list to be processed.
    :return: A list without duplicates.
    """

    if not isinstance(origin_list, list):
        return origin_list

    objs = []
    for obj in origin_list:
        if obj not in objs:
            objs.append(obj)

    return objs


def random_user_agent() -> str:
    """
    Generates a random user agent to bypass Python blockades
    """

    return secrets.choice(USER_AGENTS)


def write_to_file(log_file: str, message: str) -> None:
    """
    Writes the given content to the specified file.
    """

    with open(log_file, 'a', encoding = 'utf-8') as f:
        f.write(message + '\n')


def has_permission(path: str, mode: str = 'r') -> bool:
    """
    Determines if a file can be accessed with the specified mode at the specified path.

    :param path: A string representing the file path to check.
    :param mode: A string representing the access mode. Default is 'w' for write access.
    :return: Returns True if the file at the given path can be accessed with the
             specified mode, False otherwise.
    """

    if not os.path.isfile(path):
        path = os.path.dirname(path)
        while not os.path.isdir(path):
            if len(path) < 5:
                break

            path = os.path.dirname(path)

        if not os.path.isdir(path):
            return False

    used_mode = PERMISSION_MODES.get(mode, os.R_OK)

    return os.access(path, used_mode)


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


def handle_exception(error_message: str, print_error: bool =\
                     True, is_app_error: bool = True,
                     long_error_message: Optional[str] = None) -> None:
    """
    Handles exceptions by logging a warning message and writing
    detailed traceback information to a file asynchronously.

    :param error_message: A brief description of the error that occurred.
    :param print_error: Whether the error should be printed in the console.
    :param is_app_error: Whether the error is in the application or not.
    :param long_error_message: The long error message, if given, no
                               traceback is requested by format_exc().
    """

    if long_error_message is None:
        long_error_message = traceback.format_exc()

    timestamp = time.strftime(r'%Y-%m-%d %H:%M:%S', time.localtime())
    error_id = generate_random_string(12, with_punctuation=False)

    if print_error:
        print(f'[flask_Captchaify Error #{error_id}'+
              f' at {timestamp}]: {error_message}')

    app_error_message = ''
    if not is_app_error:
        app_error_message = '\n(This is not an application error)'

    long_error_message = '----- Error #' + str(error_id) + ' at ' + timestamp\
                         + f' -----{app_error_message}\n' + long_error_message

    if not os.path.isfile(LOG_FILE):
        long_error_message = 'If you find a new error, report it here: '+\
                             'https://github.com/tn3w/flask_Captchaify/issues\n'\
                              + long_error_message

    WRITE_EXECUTOR.submit(write_to_file, LOG_FILE, long_error_message)


def validate_captcha_response(response: dict, expected_hostname: str) -> bool:
    """
    Validates the captcha response data.

    :param response: The JSON response from the captcha service.
    :param expected_hostname: The expected hostname to validate against.
    :return: A bool containing validation results.
    """

    if not response.get('success', False) or\
        ('error-codes' in response and len(response['error-codes']) != 0) or\
            ('hostname' in response and get_domain_from_url(
                response.get('hostname', '')) != expected_hostname):
        return False

    timestamp_str = response.get('challenge_ts', None)
    if not isinstance(timestamp_str, str):
        return True

    try:
        if 'Z' in timestamp_str:
            timestamp_str = timestamp_str.replace('Z', '+0000')

        challenge_time = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S%z')
    except ValueError:
        return True

    if challenge_time.tzinfo is None:
        challenge_time = challenge_time.replace(tzinfo=timezone.utc)

    current_time = datetime.now(timezone.utc)
    if current_time - challenge_time > timedelta(minutes=3):
        return False

    return True


###################
#### URL Tools ####
###################


def get_char(url: str) -> str:
    """
    Returns a '?' if the URL does not contain one, otherwise returns a '&'.
    
    :param url: The URL to check.
    :return: A '?' if the URL does not contain one, otherwise returns a '&'.
    """

    if '?' not in url:
        return '?'

    return '&'


def extract_args(url):
    """
    Extracts the query parameters from a given URL and returns them as a dictionary.

    Parameters:
    url (str): The URL string from which to extract the query parameters.

    Returns:
    dict: A dictionary containing the query parameters and their corresponding values.
    """

    parsed_url = urlparse(url)
    query = parsed_url.query

    query_params = parse_qs(query)

    for key, value in query_params.items():
        if len(value) == 1:
            query_params[key] = query_params[key][0]

    arg_string = ''
    for key, value in query_params.items():
        arg_string += f'{get_char(arg_string)}{key}={value}'

    return arg_string


def remove_args_from_url(url: str, args_to_remove: list) -> str:
    """
    Removes specified arguments from the given URL.

    :param url: The URL from which to remove the arguments.
    :param args_to_remove: The list of arguments to remove.
    :return: The URL without the specified arguments.
    """

    parsed_url = urlparse(url)
    args = parse_qs(parsed_url.query)

    for arg in args_to_remove:
        args.pop(arg, None)

    new_query_string = urlencode(args, doseq=True)
    url_without_args = urlunparse(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path,
         parsed_url.params, new_query_string, parsed_url.fragment)
    )

    return url_without_args


def extract_path_and_args(url: str) -> str:
    """
    Extracts the path and arguments from the given URL.

    :param url: The URL from which to extract the path and arguments.
    :return: The path and arguments extracted from the URL
    """

    parsed_url = urlparse(url)

    path = parsed_url.path

    args_dict = parse_qs(parsed_url.query)
    args_str = urlencode(args_dict, doseq=True)

    path_and_args = path
    if args_str:
        path_and_args += '?' + args_str

    return path_and_args


def get_domain_from_url(url: str) -> str:
    """
    Extracts the domain or IP address from a given URL, excluding the port if present.

    :param url: The URL from which to extract the domain or IP address.
    :return: The domain or IP address extracted from the URL.
    """

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed_url = urlparse(url)
    netloc = parsed_url.netloc

    if ':' in netloc:
        netloc = netloc.split(':')[0]

    domain_parts = netloc.split('.')
    if all(part.isdigit() for part in netloc.split('.')):
        return netloc

    if len(domain_parts) > 2:
        domain = '.'.join(domain_parts[-2:])
    else:
        domain = netloc

    return domain


def get_return_path(request: Request, default: Optional[str] = None) -> Optional[str]:
    """
    Extracts the return path from the request parameters or form data.

    :param request: The HTTP request object.
    :param default: The default return path to be returned
                    if no return path is found in the request.
    :return: The extracted return path, or the default value if no return path is found.
    """

    if request.args.get('return_path') is not None:
        return extract_path_and_args(request.args.get('return_path'))

    if request.form.get('return_path') is not None:
        return extract_path_and_args(request.form.get('return_path'))

    return default


def get_return_url(return_path: str, request: Request) -> Optional[str]:
    """
    Constructs the return URL based on the return path extracted from the request.

    :param request: The HTTP request object.
    :return: The constructed return URL, or None if the return path is not available.
    """

    scheme = request.headers.get('X-Forwarded-Proto', '')
    if scheme not in ['https', 'http']:
        if request.is_secure:
            scheme = 'https'
        else:
            scheme = 'http'

    domain = urlparse(request.url).netloc
    return urljoin(scheme + '://' + domain, return_path)


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


def remove_all_args_from_url(url: str) -> str:
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


#####################
#### Image Tools ####
#####################


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
    :return: A data URL representing the image in Base64 Web Format
    """

    encoded_image = b64encode(image_data).decode('utf-8')

    data_url = f'data:image/png;base64,{encoded_image}'

    return data_url


def manipulate_image_bytes(image_data: bytes, is_small: bool = False,
                           hardness: int = 1) -> bytes:
    """
    Manipulates an image represented by bytes to create a distorted version.

    :param image_data: The bytes representing the original image.
    :param is_small: Whether the image should be resized to 100x100 or not.
    :param hardness: A number between 1 and 5 that determines the distortion factor.
    :return: The bytes of the distorted image.
    """

    img = cv2.imdecode(np.frombuffer(image_data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Image data could not be decoded.")

    height, width = img.shape[:2]

    if hardness > 3:
        num_dots = np.random.randint(20, 50) * (hardness - 3)
        dot_coords = np.random.randint(0, [width, height], size=(num_dots, 2))
        colors = np.random.randint(0, 256, size=(num_dots, 3))

        for (x, y), color in zip(dot_coords, colors):
            img[y, x] = color

        num_lines = np.random.randint(20, 50) * (hardness - 3)
        start_coords = np.random.randint(0, [width, height], size=(num_lines, 2))
        end_coords = np.random.randint(0, [width, height], size=(num_lines, 2))
        colors = np.random.randint(0, 256, size=(num_lines, 3))

        for (start, end), color in zip(zip(start_coords, end_coords), colors):
            cv2.line(img, tuple(start), tuple(end), color.tolist(), 1)

    max_shift = max(3, hardness)
    x_shifts = np.random.randint(-max(2, hardness - 1), max_shift, size=(height, width))
    y_shifts = np.random.randint(-max(2, hardness - 1), max_shift, size=(height, width))

    map_x, map_y = np.meshgrid(np.arange(width), np.arange(height))
    map_x = (map_x + x_shifts) % width
    map_y = (map_y + y_shifts) % height

    shifted_img = cv2.remap(
        img, map_x.astype(np.float32),
        map_y.astype(np.float32), cv2.INTER_LINEAR
    )
    shifted_img_hsv = cv2.cvtColor(shifted_img, cv2.COLOR_BGR2HSV)

    shifted_img_hsv[..., 1] = np.clip(shifted_img_hsv[..., 1] * (1 + hardness * 0.06), 0, 255)
    shifted_img_hsv[..., 2] = np.clip(shifted_img_hsv[..., 2] * (1 - hardness * 0.03), 0, 255)

    shifted_img = cv2.cvtColor(shifted_img_hsv, cv2.COLOR_HSV2BGR)
    shifted_img = cv2.GaussianBlur(shifted_img, (5, 5), hardness * 0.1)

    size = 100 if is_small else 200
    shifted_img = cv2.resize(shifted_img, (size, size), interpolation=cv2.INTER_LINEAR)

    _, output_bytes = cv2.imencode('.png', shifted_img)
    if not _:
        raise ValueError("Image encoding failed.")

    return output_bytes.tobytes()


######################
#### Search Tools ####
######################


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

    normalized_query = normalize_string(query).lower()
    if not normalized_query.strip():
        return languages

    matching_languages = []
    full_match = None

    for language in languages:
        normalized_language_name = normalize_string(language['name']).lower()
        distance = levenshtein_distance(normalized_language_name, normalized_query)

        if normalized_language_name == normalized_query:
            full_match = language
        elif normalized_query in normalized_language_name or\
            (distance <= 2 and language['code'] not in ['ja', 'hi', 'bn']):
            matching_languages.append(language)

        if language['code'] == normalized_query:
            full_match = language
            break

        for lang_code, lang_name in language['names'].items():
            normalized_lang_name = normalize_string(lang_name).lower()
            distance = levenshtein_distance(normalized_query, normalized_lang_name)

            if normalized_query == normalized_lang_name:
                full_match = language
                break

            if len(normalized_query) <= 4:
                continue

            if normalized_query in normalized_lang_name or\
                (distance <= 2 and lang_code not in ['ja', 'hi', 'bn']):
                matching_languages.append(language)
                break

    if full_match:
        matching_languages = [full_match]

    matching_languages = remove_duplicates(matching_languages)

    matching_languages.sort(key=lambda x: levenshtein_distance(
        normalized_query, normalize_string(x['name'])
    ))

    return matching_languages


#################
#### Classes ####
#################


file_locks = {}


class Json:
    """
    Class for loading / saving JavaScript Object Notation (= JSON)
    """

    def __init__(self) -> None:
        self.data = {}


    def load(self, file_path: str, default: Optional[
             Union[dict, list]] = None) -> Union[dict, list]:
        """
        Function to load a JSON file securely.

        :param file_path: The JSON file you want to load
        :param default: Returned if no data was found
        """

        if default is None:
            default = {}

        if not os.path.isfile(file_path)\
            or not has_permission(file_path, 'r'):
            return default

        if file_path not in file_locks:
            file_locks[file_path] = threading.Lock()

        with file_locks[file_path]:
            try:
                with open(file_path, 'r', encoding = 'utf-8') as file:
                    data = json.load(file)
            except Exception as exc:
                handle_exception(exc, print_error = False, is_app_error = False)

                if self.data.get(file_path) is not None:
                    self.dump(self.data[file_path], file_path)
                    return self.data
                return default
        return data


    def dump(self, data: Union[dict, list], file_path: str) -> bool:
        """
        Function to save a JSON file securely.
        
        :param data: The data to be stored should be either dict or list
        :param file_path: The file to save to
        """

        file_directory = os.path.dirname(file_path)
        if not os.path.isdir(file_directory)\
            or not has_permission(file_directory, 'w'):
            return False

        if file_path not in file_locks:
            file_locks[file_path] = threading.Lock()

        self.data[file_path] = data
        WRITE_EXECUTOR.submit(self._write, data, file_path)

        return True

    @staticmethod
    def _write(data: Union[dict, list], file_path: str) -> None:
        """
        Function to save a JSON file securely.
        
        :param data: The data to be stored should be either dict or list
        :param file_path: The file to save to
        """

        try:
            with file_locks[file_path]:
                with open(file_path, 'w', encoding = 'utf-8') as file:
                    json.dump(data, file)
        except Exception as exc:
            handle_exception(exc, is_app_error = False)


class Pickle:
    """
    Class for loading / saving Pickle
    """

    def __init__(self) -> None:
        self.data = {}


    def load(self, file_path: str, default: Optional[
             Union[dict, list]] = None) -> Union[dict, list]:
        """
        Function to load a Pickle file securely.

        :param file_path: The Pickle file you want to load
        :param default: Returned if no data was found
        """

        if default is None:
            default = {}

        if not os.path.isfile(file_path)\
            or not has_permission(file_path, 'r'):
            return default

        if file_path not in file_locks:
            file_locks[file_path] = threading.Lock()

        with file_locks[file_path]:
            try:
                with open(file_path, 'rb') as file:
                    data = pickle.load(file)
            except Exception as exc:
                handle_exception(exc, print_error = False, is_app_error = False)

                if self.data.get(file_path) is not None:
                    self.dump(self.data[file_path], file_path)
                    return self.data
                return default

        return data


    def dump(self, data: Union[dict, list], file_path: str) -> bool:
        """
        Function to save a Pickle file securely.
        
        :param data: The data to be stored should be either dict or list
        :param file_path: The file to save to
        """

        file_directory = os.path.dirname(file_path)
        if not os.path.isdir(file_directory)\
            or not has_permission(file_directory, 'w'):
            return False

        if file_path not in file_locks:
            file_locks[file_path] = threading.Lock()

        self.data[file_path] = data
        WRITE_EXECUTOR.submit(self._write, data, file_path)

        return True


    @staticmethod
    def _write(data: Union[dict, list], file_path: str) -> None:
        """
        Function to save a Pickle file securely.
        
        :param data: The data to be stored should be either dict or list
        :param file_path: The file to save to
        """

        try:
            with file_locks[file_path]:
                with open(file_path, 'wb') as file:
                    pickle.dump(data, file)
        except Exception as exc:
            handle_exception(exc, is_app_error = False)

JSON = Json()
PICKLE = Pickle()
