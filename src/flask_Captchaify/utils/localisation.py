"""
localisation.py

This is a module for translating text and html.

License:  GNU General Public License v3.0
    https://github.com/tn3w/flask_Captchaify/blob/master/LICENSE
Source:   https://github.com/tn3w/flask_Captchaify
"""

import re
from typing import Final, Optional, Tuple, Any

from lxml.html import fromstring, tostring
from googletrans import Translator as GoogleTranslator

try:
    from utils.logger import log
    from utils.files import TRANSLATIONS_CACHE_FILE_PATH, PICKLE
except ImportError:
    try:
        from src.flask_Captchaify.utils.logger import log
        from src.flask_Captchaify.utils.files import (
            TRANSLATIONS_CACHE_FILE_PATH, PICKLE
        )
    except ImportError:
        from logger import log
        from files import TRANSLATIONS_CACHE_FILE_PATH, PICKLE


GOOGLE_TRANSLATOR: Final[GoogleTranslator] = GoogleTranslator()

LANGUAGE_CODES: Final[list] = [
    "af", "sq", "am", "ar", "hy", "az", "eu", "be", "bn", "bs", "bg", "ca", "ceb", "ny",
    "zh-cn", "zh-tw", "co", "hr", "cs", "da", "nl", "en", "eo", "et", "tl", "fi", "fr",
    "fy", "gl", "ka", "de", "el", "gu", "ht", "ha", "haw", "iw", "he", "hi", "hmn", "hu",
    "is", "ig", "id", "ga", "it", "ja", "jw", "kn", "kk", "km", "ko", "ku", "ky", "lo",
    "la", "lv", "lt", "lb", "mk", "mg", "ms", "ml", "mt", "mi", "mr", "mn", "my", "ne",
    "no", "or", "ps", "fa", "pl", "pt", "pa", "ro", "ru", "sm", "gd", "sr", "st", "sn",
    "sd", "si", "sk", "sl", "so", "es", "su", "sw", "sv", "tg", "ta", "te", "th", "tr",
    "tk", "uk", "ur", "ug", "uz", "vi", "cy", "xh", "yi", "yo", "zu"
]
EMOJI_PATTERN = re.compile(
    "["
    "\U0001F600-\U0001F64F"  # emoticons
    "\U0001F300-\U0001F5FF"  # symbols & pictographs
    "\U0001F680-\U0001F6FF"  # transport & map symbols
    "\U0001F700-\U0001F77F"  # alchemical symbols
    "\U0001F780-\U0001F7FF"  # Geometric Shapes Extended
    "\U0001F800-\U0001F8FF"  # Supplemental Arrows-C
    "\U0001F900-\U0001F9FF"  # Supplemental Symbols and Pictographs
    "\U0001FA00-\U0001FA6F"  # Chess Symbols
    "\U0001FA70-\U0001FAFF"  # Symbols and Pictographs Extended-A
    "\U00002702-\U000027B0"  # Dingbats
    "\U000024C2-\U0001F251"
    "]+", flags=re.UNICODE
)


def is_emoji(text: Optional[str]) -> bool:
    """
    Checks if a given text contains an emoji.

    Args:
        text (Optional[str]): The text to check against.

    Returns:
        bool: True if the text contains an emoji, False otherwise.
    """

    if not isinstance(text, str):
        return False

    is_found = re.search(EMOJI_PATTERN, text)
    return bool(is_found)


def extract_emojis(text: str) -> Tuple[str, list]:
    """
    Extracts emojis from text.

    Args:
        text (Optional[str]): The text to extract emojis from.

    Returns:
        Tuple[str, list]: The text with emojis removed and a
            list of emojis and their positions.
    """

    emojis = []
    positions = []

    for match in EMOJI_PATTERN.finditer(text):
        emojis.append(match.group())
        positions.append(match.start())

    text_without_emojis = EMOJI_PATTERN.sub(r"", text)
    return text_without_emojis, emojis, positions


def insert_emojis(text: str, emojis: list, positions: list) -> str:
    """
    Inserts emojis into text.

    Args:
        text (str): The text to insert emojis into.
        emojis (list): The emojis to insert.
        positions (list): The positions to insert the emojis.

    Returns:
        str: The text with emojis inserted.
    """

    for emoji, position in zip(emojis, positions):
        text = text[:position] + emoji + " " + text[position:]

    return text


def load_cached_translations() -> dict:
    """
    Load cached translations from a file.

    Returns:
        dict: A dictionary containing cached translations.
    """

    return PICKLE.load(TRANSLATIONS_CACHE_FILE_PATH, {})


def dump_cached_translations(translations: dict) -> bool:
    """
    Save translations to a cache file.

    Args:
        translations (dict): A dictionary containing translations to be cached.

    Returns:
        bool: True if the translations were successfully saved, 
              False otherwise.
    """

    return PICKLE.dump(translations, TRANSLATIONS_CACHE_FILE_PATH)


def get_cached_translation(key: tuple) -> Optional[str]:
    """
    Retrieve a cached translation by its key.

    Args:
        key (tuple): A tuple representing the translation key, typically 
                     consisting of the text and language codes.

    Returns:
        Optional[str]: The cached translation if found, or None if not.
    """

    translations = load_cached_translations()
    return translations.get(key, None)


def add_cached_translation(key: tuple, value: str) -> bool:
    """
    Add a new translation to the cache.

    Args:
        key (tuple): A tuple representing the translation key, typically 
                     consisting of the text and language codes.
        value (str): The translation value to be cached.

    Returns:
        bool: True if the translation was successfully added and saved, 
              False otherwise.
    """

    translations = load_cached_translations()
    translations[key] = value

    dump_cached_translations(translations)


def normalize_language_code(code: str) -> str:
    """
    Normalize a language code to a standard format.

    Args:
        code (str): The language code to be normalized.

    Returns:
        str: The normalized language code, or "en" if the code is invalid.
    """

    if code not in LANGUAGE_CODES:
        return "en"

    return code


def translate(text: str, from_lang: str = "en", to_lang: str = "en") -> str:
    """
    Translate text from one language to another using a translation service.

    Args:
        text (str): The text to be translated.
        from_lang (str, optional): The language code of the source text 
                                    (default is "en" for English).
        to_lang (str, optional): The language code of the target language 
                                  (default is "en" for English).

    Returns:
        str: The translated text if successful, or the original text 
             if the translation fails or if the source and target languages 
             are the same.
    """

    from_lang, to_lang = normalize_language_code(from_lang), normalize_language_code(to_lang)
    if from_lang == to_lang:
        return text

    key = (text, from_lang, to_lang)
    if translation := get_cached_translation(key):
        return translation

    try:
        translated = GOOGLE_TRANSLATOR.translate(text, src=from_lang, dest=to_lang).text

        if translated:
            add_cached_translation(key, translated)
            return translated

    except Exception:
        log(f"{text} was unsuccessfully translated from {from_lang} to {to_lang}", level = 4)

    return text


class Translator:
    """
    A class for translating text within HTML elements.
    """


    @staticmethod
    def translate_text_in_element(element: Any, from_lang: str, to_lang: str,
                                  translated_elements: Optional[set] = None) -> None:
        """
        Translate the text content of an HTML element and its children.

        Args:
            element (Any): The HTML element to translate.
            from_lang (str): The language code of the source text.
            to_lang (str): The language code of the target language.
            translated_elements (Optional[set], optional): A set to keep 
                track of translated elements.
        """

        if translated_elements is None:
            translated_elements = set()

        if element.text and element not in translated_elements:
            element.text = translate(element.text.strip(), from_lang, to_lang)
            translated_elements.add(element)

        for child in element:
            Translator.translate_text_in_element(child, from_lang, to_lang, translated_elements)
            if not child.tail or child in translated_elements:
                continue

            child.tail = translate(child.tail.strip(), from_lang, to_lang)
            translated_elements.add(child)


    @staticmethod
    def translate_attributes(element: Any, from_lang: str, to_lang: str) -> None:
        """
        Translate specific attributes of an HTML element.

        Args:
            element (Any): The HTML element whose attributes are to be translated.
            from_lang (str): The language code of the source text.
            to_lang (str): The language code of the target language.
        """

        for attr in ['placeholder', 'content']:
            if attr not in element.attrib or 'ntr' in element.attrib:
                continue

            element.attrib[attr] = translate(
                element.attrib[attr].strip(), from_lang, to_lang
            )


    @staticmethod
    def translate_html(html: str, from_lang: str, to_lang: str) -> str:
        """
        Translate the text and attributes in an HTML string.

        Args:
            html (str): The HTML string to be translated.
            from_lang (str): The language code of the source text.
            to_lang (str): The language code of the target language.

        Returns:
            str: The translated HTML string.
        """

        tree = fromstring(html)

        for tag in tree.xpath(
            "//h1 | //h2 | //h3 | //h4 | //h5 | //h6 | //a | //p | //button | //span"):

            if 'ntr' in tag.attrib:
                continue

            Translator.translate_text_in_element(tag, from_lang, to_lang)

        for input_tag in tree.xpath("//input[@placeholder]"):
            if 'ntr' not in input_tag.attrib:
                Translator.translate_attributes(input_tag, from_lang, to_lang)

        head = tree.find(".//head")
        if head is not None:
            title_tag = head.find("title")
            if title_tag is not None:
                title_tag.text = translate(title_tag.text.strip(), from_lang, to_lang)

            for meta_tag in head.xpath(
                ".//meta[@name='title' or @name='description' or @name='keywords']"
                ):

                Translator.translate_attributes(meta_tag, from_lang, to_lang)

        translated_html = tostring(tree, encoding="unicode", method="html")
        return translated_html
