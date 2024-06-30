"""
-~- WebToolbox Module -~-
This module contains functions for the web
such as HTML manipulation. It is part of the
flask_Captchaify module for Flask applications at
https://github.com/tn3w/flask_Captchaify.

The original GPL-3.0 licence applies.
"""

import os
import re
from typing import Final, Optional, Tuple
from urllib.parse import urlparse, parse_qs, quote
from bs4 import BeautifulSoup, Tag, NavigableString
from googletrans import Translator as GoogleTranslator
from jinja2 import Environment, FileSystemLoader, select_autoescape, Undefined
from .utils import PICKLE, JSON, TEMPLATE_DIR, ASSETS_DIR, DATA_DIR,\
    handle_exception, get_domain_from_url
from .req_info import RequestInfo


LANGUAGES: Final[list] = JSON.load(os.path.join(ASSETS_DIR, 'languages.json'), [])
LANGUAGE_CODES: Final[list] = [language['code'] for language in LANGUAGES]
google_translator = GoogleTranslator()

TEMPLATE_ASSETS_DIR: Final[str] = os.path.join(TEMPLATE_DIR, 'assets')
TRANSLATIONS_FILE_PATH: Final[str] = os.path.join(DATA_DIR, 'translations.pkl')

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


class SilentUndefined(Undefined):
    """
    Class to not get an error when specifying a non-existent argument
    """

    def _fail_with_undefined_error(self, *args, **kwargs):
        return None


def render_html(html: str, **kwargs) -> str:
    """
    Function to render HTML content

    :param html: The content of the page as html.
    :param kwargs: Arguments to be inserted into the Template with Jinja2.
    """

    env = Environment(undefined = SilentUndefined)
    template = env.from_string(html)

    return template.render(**kwargs)


def asset(asset_name: str, **kwargs) -> Optional[str]:
    """
    Function to render an asset

    :param asset_name: The name of the asset
    :param kwargs: Arguments to be inserted into the Template with Jinja2.
    """

    if asset_name is None:
        return None

    file_path = os.path.join(
        TEMPLATE_ASSETS_DIR, asset_name +\
            ('.j2' if not asset_name.endswith('.j2') else '')
    )

    if not os.path.isfile(file_path):
        return None

    with open(file_path, "r", encoding = "utf-8") as readable_file:
        html = readable_file.read()

    return render_html(html, **kwargs)


def render_template(template_dir: str, file_name: str,
                    template_language: str = 'en', client_language: str = 'en', **kwargs) -> str:
    """
    Renders a template file into HTML content, optionally translating it to the specified language.

    :param template_dir: The directory path where template files are located.
    :param file_name: The name of the template file to render.
    :param template_language: The language to translate the template to.
    :param client_language: The language to translate the template to.
    :param kwargs: Arguments to be inserted into the WebToolbox with Jinja2.

    :return: The rendered HTML content of the template.
    """

    if template_language is None:
        template_language = "en"

    html = WebToolbox.render_template(template_dir, file_name, html = None, **kwargs)
    html = Translator.translate_html(html, template_language, client_language)
    html = WebToolbox.minimize(html)

    return html


def is_emoji(text: str) -> bool:
    """
    Checks if a given text is an emoji

    :param text: The text to check
    :return: True if the text contains an emoji, False otherwise
    """

    if text is None:
        return False

    is_found = re.search(EMOJI_PATTERN, text)
    return bool(is_found)


def extract_emojis(text: str) -> Tuple[str, list, list]:
    """
    Extracts emojis from text

    :param text: The text to extract emojis from
    :return: The text with emojis removed and a list of emojis and their positions
    """

    emojis = []
    positions = []

    for match in EMOJI_PATTERN.finditer(text):
        emojis.append(match.group())
        positions.append(match.start())

    text_without_emojis = EMOJI_PATTERN.sub(r'', text)
    return text_without_emojis, emojis, positions


def insert_emojis(text: str, emojis: list, positions: list) -> str:
    """
    Inserts emojis into text

    :param text: The text to insert emojis into
    :param emojis: The emojis to insert
    :param positions: The positions to insert the emojis
    :return: The text with emojis inserted
    """

    for emoji, position in zip(emojis, positions):
        text = text[:position] + emoji + ' ' + text[position:]
    return text


class Translator:
    """
    Class containing static methods for translating text.
    """


    @staticmethod
    def translate(text_to_translate: str, from_lang: str, to_lang: str) -> str:
        """
        Function to translate a text based on a translation file

        :param text_to_translate: The text to translate
        :param from_lang: The language of the text to be translated
        :param to_lang: Into which language the text should be translated
        """

        text_to_translate = text_to_translate.strip('\n ')

        if from_lang == to_lang or not text_to_translate:
            return text_to_translate

        translations = PICKLE.load(TRANSLATIONS_FILE_PATH, [])

        for translation in translations:
            if translation["text_to_translate"] == text_to_translate\
                and translation["from_lang"] == from_lang\
                    and translation["to_lang"] == to_lang:
                return translation["translated_output"]

        try:
            translated_output = google_translator.translate(
                text_to_translate, src=from_lang, dest=to_lang
            ).text

            if translated_output is None:
                return text_to_translate
        except Exception as exc:
            handle_exception(exc, is_app_error = False)
            return text_to_translate

        translation = {
            "text_to_translate": text_to_translate, 
            "from_lang": from_lang,
            "to_lang": to_lang, 
            "translated_output": translated_output
        }
        translations.append(translation)

        PICKLE.dump(translations, TRANSLATIONS_FILE_PATH)

        return translated_output


    @staticmethod
    def translate_tag(html_tag: Tag, from_lang: str, to_lang: str):
        """
        Function to translate the text within a given HTML tag.

        :param html_tag: The HTML tag to be translated.
        :param from_lang: The language of the text to be translated.
        :param to_lang: Into which language the text should be translated.

        :return: The translated HTML tag.
        """

        translated_texts = []
        is_first_element = True

        for element in html_tag.descendants:
            if element.getText().strip() == "":
                continue

            if isinstance(element, NavigableString) and is_first_element:
                if is_emoji(element) and len(element.strip()) == 1:
                    translated_texts.append(
                        (element, element)
                    )
                else:
                    if element.parent.name not in ['script', 'style']:
                        translated_texts.append(
                            (element, Translator.translate(element, from_lang, to_lang))
                        )
                    is_first_element = False

            elif isinstance(element, Tag):
                if hasattr(element, 'attrs') and 'ntr' in element.attrs:
                    continue

                for attr, value in element.attrs.items():
                    if isinstance(value, list):
                        translated_values = [
                            Translator.translate(val, from_lang, to_lang)
                            for val in value
                        ]
                        element.attrs[attr] = translated_values
                    else:
                        element.attrs[attr] = Translator.translate(value, from_lang, to_lang)

        for original, translated in translated_texts:
            original.replace_with(translated)

        translated_html = str(html_tag)
        return translated_html


    @staticmethod
    def translate_html(html: str, from_lang: str, to_lang: str) -> Tag:
        """
        Function to translate a page into the correct language.

        :param html: The content of the page as html.
        :param from_lang: The language of the text to be translated.
        :param to_lang: Into which language the text should be translated.

        :return: The translated HTML tag.
        """

        soup = BeautifulSoup(html, 'html.parser')

        tags = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5',
                              'h6', 'a', 'p', 'button', 'span'])
        for tag in tags:
            if str(tag) and 'ntr' not in tag.attrs:
                Translator.translate_tag(tag, from_lang, to_lang)

        inputs = soup.find_all('input')
        for input_tag in inputs:
            if input_tag.has_attr('placeholder') and 'ntr' not in input_tag.attrs:
                input_tag['placeholder'] = Translator.translate(
                    input_tag['placeholder'].strip(), from_lang, to_lang
                    )

        head_tag = soup.find('head')
        if head_tag:
            title_element = head_tag.find('title')
            if title_element:
                text_with_emojis = title_element.text.strip()
                clean_title, emojis, positions = extract_emojis(text_with_emojis)

                translated_title = Translator.translate(clean_title, from_lang, to_lang)
                final_title = insert_emojis(translated_title, emojis, positions)

                title_element.string = final_title

            meta_title = head_tag.find('meta', attrs={'name': 'title'})
            if meta_title and 'content' in meta_title.attrs:
                meta_title['content'] = Translator.translate(
                    meta_title['content'].strip(), from_lang, to_lang
                )

            meta_description = head_tag.find('meta', attrs={'name': 'description'})
            if meta_description and 'content' in meta_description.attrs:
                meta_description['content'] = Translator.translate(
                    meta_description['content'].strip(), from_lang, to_lang
                )

            meta_keywords = head_tag.find('meta', attrs={'name': 'keywords'})
            if meta_keywords and 'content' in meta_keywords.attrs:
                meta_keywords['content'] = Translator.translate(
                    meta_keywords['content'].strip(), from_lang, to_lang
                )

        translated_html = soup.prettify()
        return translated_html


class WebToolbox:
    """
    Class containing static methods for web development tasks,
    such as minimizing HTML, translating text, adding arguments to links and forms,
    and rendering HTML templates.
    """


    @staticmethod
    def _minimize_tag_content(html: str, tag: str) -> str:
        """
        Minimizes the content of a given tag
        
        :param html: The HTML page where the tag should be minimized
        :param tag: The HTML tag e.g. `script` or `style`
        :return: The HTML page with minimized tag content
        """

        tag_pattern = rf'(<{tag}\b[^>]*>)(.*?)(<\/{tag}>)'

        def minimize_tag_content(match: re.Match):
            opening_tag = match.group(1)
            content = match.group(2)
            closing_tag = match.group(3)

            minimized_content = re.sub(r'\s+', ' ', content)

            return f'{opening_tag}{minimized_content}{closing_tag}'

        return re.sub(tag_pattern, minimize_tag_content, html, flags=re.DOTALL | re.IGNORECASE)


    @staticmethod
    def minimize(html: str) -> str:
        """
        Minimizes an HTML page

        :param html: The content of the page as html
        """

        html = re.sub(r'<!--(.*?)-->', '', html, flags=re.DOTALL)
        html = re.sub(r'\s+', ' ', html)

        html = WebToolbox._minimize_tag_content(html, 'script')
        html = WebToolbox._minimize_tag_content(html, 'style')
        return html


    @staticmethod
    def add_arguments(html: str, request_info: RequestInfo, **kwargs) -> str:
        """
        Function to add arguments to the url

        :param html: The content of the page as html
        :param request_info: The request information
        :param kwargs: The arguments to add
        """

        soup = BeautifulSoup(html, 'html.parser')

        def url_has_argument(url, argument_name):
            """
            Check if a URL contains a specific argument.

            :param url: The URL to check.
            :param argument_name: The name of the argument to look for.
            :return: True if the URL contains the argument, False otherwise.
            """

            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            return argument_name in query_params

        for anchor in soup.find_all('a'):
            if not 'href' in anchor.attrs:
                continue

            if '://' in anchor['href']:
                anchor_host = get_domain_from_url(anchor['href'])
                if anchor_host != get_domain_from_url(request_info.get_url()):
                    continue
            elif not anchor['href'].startswith(('/', '#', '?', '&')):
                continue

            for arg, content in kwargs.items():
                if arg == 'template':
                    continue

                if not url_has_argument(anchor['href'], arg):
                    special_character = '?' if '?' not in anchor['href'] else '&'
                    anchor['href'] += f'{special_character}{arg}={quote(content)}'

        for form in soup.find_all('form'):
            action = form.get('action')
            if action:
                for arg, content in kwargs.items():
                    if not url_has_argument(action, arg):
                        special_character = '?' if '?' not in action else '&'
                        form['action'] += f'{special_character}{arg}={quote(content)}'

            existing_names = {input_tag.get('name') for input_tag in form.find_all('input')}
            added_input = '\n'.join(f'<input type="hidden" name="{arg}" value="{content}">'
                                    for arg, content in kwargs.items() if arg not in existing_names)

            form_button = form.find('button')
            if form_button:
                form_button.insert_before(BeautifulSoup(added_input, 'html.parser'))
            else:
                form.append(BeautifulSoup(added_input, 'html.parser'))

        html_with_args = soup.prettify()
        return html_with_args


    @staticmethod
    def render_template(template_dir: str, file_name: Optional[str] = None,
                        html: Optional[str] = None, **kwargs) -> str:
        """
        Function to render a HTML template (= insert arguments / translation / minimization)

        :param template_dir: The directory path where template files are located.
        :param file_name: The name of the template file to render. (Optional)
        :param html: The content of the page as html. (Optional)
        :param kwargs: Arguments to be inserted into the WebToolbox with Jinja2.
        """

        file_path = os.path.join(template_dir, file_name)

        if file_path is None and html is None:
            raise ValueError("Arguments 'file_path' and 'html' are None")

        if not file_path is None:
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"File `{file_path}` does not exist")

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

        html = template.render(**kwargs)

        return html
