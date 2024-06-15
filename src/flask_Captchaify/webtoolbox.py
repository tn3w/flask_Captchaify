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
from typing import Optional
from urllib.parse import urlparse, parse_qs, quote
from googletrans import Translator
from bs4 import BeautifulSoup, Tag
from jinja2 import Environment, FileSystemLoader, select_autoescape, Undefined
from .utils import PICKLE, JSON, ASSETS_DIR, DATA_DIR, handle_exception,\
    get_domain_from_url
from .req_info import RequestInfo


LANGUAGES = JSON.load(os.path.join(ASSETS_DIR, 'languages.json'), [])
LANGUAGE_CODES = [language['code'] for language in LANGUAGES]
TRANSLATIONS_FILE_PATH = os.path.join(DATA_DIR, 'translations.pkl')
translator = Translator()


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
    html = WebToolbox.translate(html, template_language, client_language)
    html = WebToolbox.minimize(html)

    return html


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

        translations = PICKLE.load(TRANSLATIONS_FILE_PATH, [])

        for translation in translations:
            if translation["text_to_translate"] == text_to_translate\
                and translation["from_lang"] == from_lang\
                    and translation["to_lang"] == to_lang:
                return translation["translated_output"]

        try:
            translated_output = translator.translate(
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
    def translate(html: str, from_lang: str, to_lang: str) -> str:
        """
        Function to translate a page into the correct language

        :param html: The content of the page as html
        :param from_lang: The language of the text to be translated
        :param to_lang: Into which language the text should be translated
        """

        def translate_tag(html_tag: Tag, from_lang: str, to_lang: str):
            """
            Function to translate the text within a given HTML tag.

            :param html_tag: The HTML tag to be translated.
            :param from_lang: The language of the text to be translated.
            :param to_lang: Into which language the text should be translated.

            :return: The translated HTML tag.
            """

            translated_texts = []
            for tag in html_tag.find_all(text = True, recursive = True):
                if hasattr(tag, 'attrs') and 'ntr' in tag.attrs:
                    continue

                if tag.parent.name not in ['script', 'style']:
                    translated_texts.append(
                        (tag, WebToolbox._translate_text(tag, from_lang, to_lang))
                    )

            for tag, translated_text in translated_texts:
                tag.replace_with(translated_text)

            translated_html = str(html_tag)
            return translated_html

        soup = BeautifulSoup(html, 'html.parser')

        tags = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5',
                              'h6', 'a', 'p', 'button', 'li', 'span'])
        for tag in tags:
            if str(tag) and 'ntr' not in tag.attrs:
                translate_tag(tag, from_lang, to_lang)

        inputs = soup.find_all('input')
        for input_tag in inputs:
            if input_tag.has_attr('placeholder') and 'ntr' not in input_tag.attrs:
                input_tag['placeholder'] = WebToolbox._translate_text(
                    input_tag['placeholder'].strip(), from_lang, to_lang
                    )

        head_tag = soup.find('head')
        if head_tag:
            title_element = head_tag.find('title')
            if title_element:
                title_element.string = WebToolbox._translate_text(
                    title_element.text.strip(), from_lang, to_lang
                    )

            meta_title = head_tag.find('meta', attrs={'name': 'title'})
            if meta_title and 'content' in meta_title.attrs:
                meta_title['content'] = WebToolbox._translate_text(
                    meta_title['content'].strip(), from_lang, to_lang
                )

            meta_description = head_tag.find('meta', attrs={'name': 'description'})
            if meta_description and 'content' in meta_description.attrs:
                meta_description['content'] = WebToolbox._translate_text(
                    meta_description['content'].strip(), from_lang, to_lang
                )

            meta_keywords = head_tag.find('meta', attrs={'name': 'keywords'})
            if meta_keywords and 'content' in meta_keywords.attrs:
                meta_keywords['content'] = WebToolbox._translate_text(
                    meta_keywords['content'].strip(), from_lang, to_lang
                )

        translated_html = soup.prettify()
        return translated_html


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

        html = template.render(**kwargs)

        return html
