"""
utilities.py

This is a module for handling html and urls.

License:  GNU General Public License v3.0
    https://github.com/tn3w/flask_Captchaify/blob/master/LICENSE
Source:   https://github.com/tn3w/flask_Captchaify
"""

import re
import os
from typing import Optional, Tuple, Any
from urllib.parse import (
    quote, urlparse, urlunparse, parse_qs, urlencode, urljoin
)

from flask import abort
from werkzeug import Request
from lxml import html as lxml_html
from jinja2 import Environment, FileSystemLoader, select_autoescape, Undefined

try:
    from utils.localisation import LANGUAGE_CODES, Translator
    from utils.files import TEMPLATE_ASSETS_DIRECTORY_PATH, read
except ImportError:
    try:
        from src.flask_Captchaify.utils.localisation import LANGUAGE_CODES, Translator
        from src.flask_Captchaify.utils.files import (
            read, TEMPLATE_ASSETS_DIRECTORY_PATH
        )
    except ImportError:
        from localisation import LANGUAGE_CODES, Translator
        from files import TEMPLATE_ASSETS_DIRECTORY_PATH, read


def minimize_html(html: str) -> str:
    """
    Minimize an HTML template by removing unnecessary whitespace, comments,
    and newlines, while also minimizing embedded <style> and <script> tags.

    Parameters:
        html (str): The input HTML string to be minimized.

    Returns:
        str: A minimized version of the input HTML string.
    """

    html = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)

    def minify_js_css(content: str) -> str:
        content = re.sub(r"\s*([{}:;,])\s*", r"\1", content)
        content = re.sub(r"\s+", " ", content)
        return content.strip()

    def minify_js(content: str) -> str:
        content = re.sub(r"\s*([{}();,:])\s*", r"\1", content)
        content = re.sub(r"\s+", " ", content)
        return content.strip()

    html = re.sub(
        r"(<style.*?>)(.*?)(</style>)",
        lambda m: m.group(1) + minify_js_css(m.group(2)) + m.group(3),
        html, flags=re.DOTALL
    )

    html = re.sub(
        r"(<script.*?>)(.*?)(</script>)",
        lambda m: m.group(1) + minify_js(m.group(2)) + m.group(3),
        html, flags=re.DOTALL
    )

    html = re.sub(r">\s+<", "><", html)
    html = html.strip()

    return html


def minimize_js(js: str) -> str:
    """
    Minimize a JavaScript string by removing unnecessary whitespace, comments,
    and newlines.
    
    Parameters:
        js (str): The input JavaScript string to be minimized.

    Returns:
        str: A minimized version of the input JavaScript string.
    """

    js = re.sub(r"//.*?\n", "", js)
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.DOTALL)

    js = re.sub(r"\s*([{}();,:])\s*", r"\1", js)
    js = re.sub(r"\s+", " ", js)

    return js.strip()


def minimize_css(css: str) -> str:
    """
    Minimize a CSS string by removing unnecessary whitespace, comments,
    and newlines.
    
    Parameters:
        css (str): The input CSS string to be minimized.

    Returns:
        str: A minimized version of the input CSS string.
    """

    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)

    css = re.sub(r"\s*([{}:;,])\s*", r"\1", css)
    css = re.sub(r"\s+", " ", css)

    return css.strip()


MINIMIZE_FUNCTIONS = {
    "html": minimize_html,
    "js": minimize_js,
    "css": minimize_css
}

def minimize(content: str, file_extension: str) -> str:
    """
    Minimize the provided content based on the file extension.

    Args:
        content (str): The content to be minimized.
        file_extension (str): The file extension of the content.

    Returns:
        str: The minimized content.
    """

    normalized_file_extension = re.sub(r'[^a-zA-Z0-9]', '', file_extension)

    return MINIMIZE_FUNCTIONS.get(normalized_file_extension, minimize_html)(content)


class SilentUndefined(Undefined):
    """
    Class to not get an error when specifying a non-existent argument
    """

    def _fail_with_undefined_error(self, *args, **kwargs) -> None:
        return None


def render_html(html: str, **kwargs) -> str:
    """
    Function to render HTML content

    Args:
        html (str): The content of the page as html.
        **kwargs: Arguments to be inserted into the Template with Jinja2.

    Returns:
        str: The rendered html.
    """

    env = Environment(undefined = SilentUndefined)
    template = env.from_string(html)

    return template.render(**kwargs)


def asset(asset_name: Optional[str], **kwargs) -> Optional[str]:
    """
    Function to render an asset

    Args:
        asset_name (Optional[str]): The name of the asset
        **kwargs: Arguments to be inserted into the Template with Jinja2.

    Returns:
        Optional[str]: The rendered asset.
    """

    if not isinstance(asset_name, str):
        return None

    file_path = os.path.join(
        TEMPLATE_ASSETS_DIRECTORY_PATH, asset_name +\
            ('.j2' if not asset_name.endswith('.j2') else '')
    )

    html = read(file_path)
    if not isinstance(html, str):
        return None

    rendered_html = render_html(html, **kwargs)
    return type_or_none(rendered_html, str)


def render_template(template_dir: str, file_name: str, template_language:\
                    Optional[str] = 'en', client_language: Optional[str] = 'en', **kwargs) -> str:
    """
    Renders a template file into HTML content, optionally translating it to the specified language.

    Args:
        template_dir (str): The directory path where template files are located.
        file_name (str): The name of the template file to render.
        template_language (str): The language to translate the template to.
        client_language (str): The language to translate the template to.
        **kwargs: Arguments to be inserted into the Template with Jinja2.

    Returns:
        str: The rendered HTML content of the template.
    """

    file_path = os.path.join(template_dir, file_name)

    loader = FileSystemLoader(template_dir)
    env = Environment(
        loader = loader,
        autoescape=select_autoescape(['html', 'xml']),
        undefined=SilentUndefined
    )

    html = read(file_path)
    if not isinstance(html, str):
        return abort(500)

    template = env.from_string(html)
    html = template.render(**kwargs)

    if template_language in LANGUAGE_CODES\
        and client_language in LANGUAGE_CODES:

        html = Translator.translate_html(html, template_language, client_language)

    html = minimize_html(html)
    return type_or_none(html, str)


def type_or_none(data: Any, required_type = Any, default: Any = None) -> Optional[Any]:
    """
    Checks whether data has the correct type, if not None is returned.

    Args:
        data (Any): The data that must have a certain type.
        required_type (Any): The requested type of data.
        default (Any): The default data which is returned if data is not required_type.

    Returns:
        Any
    """

    if not isinstance(data, required_type):
        return default

    return data


def dict_remove_type(dictionary: dict, value_type: Any = str,
                     default: Any = False) -> Tuple[dict, Any]:
    """
    Removes all keys and value pairs that have not the correct type.

    Args:
        dictionary (dict): The dict that contains the values that must have a certain type.
        value_type (Any): The requested type of the values.
        default (Any): The default data which is returned if the dict is empty.

    Returns:
        Tuple[dict, Any]: Dictionary or the default value.
    """

    return_dict = {}

    for key, value in dictionary.items():
        if type_or_none(value, value_type) is None:
            continue

        return_dict[key] = value

    if default is not False and len(return_dict) < 1:
        return default

    return return_dict


def get_char(url: str) -> str:
    """
    Determines the appropriate character to append to a URL based on its current content.

    Args:
        url (str): The URL to check.

    Returns:
        str: A '?' if the URL does not contain one, otherwise returns '&'.
    """

    return '?' if '?' not in url else '&'


def url_has_argument(url: str, argument_name: str) -> bool:
    """
    Checks if a URL contains a specific argument.

    Args:
        url (str): The URL to check.
        argument_name (str): The name of the argument to look for.

    Returns:
        bool: True if the URL contains the argument, False otherwise.
    """

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    return argument_name in query_params


def extract_args(url: str) -> str:
    """
    Extracts the query parameters from a URL and returns them as a string.

    Args:
        url (str): The URL string to extract parameters from.

    Returns:
        str: A string of query parameters and their values.
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
    Removes specified arguments from a URL.

    Args:
        url (str): The URL to modify.
        args_to_remove (List[str]): A list of argument names to remove.

    Returns:
        str: The URL with the specified arguments removed.
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
    Extracts the path and arguments from a URL.

    Args:
        url (str): The URL to extract from.

    Returns:
        str: A string containing the path and query arguments.
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
    Extracts the domain or IP address from a URL, excluding the port.

    Args:
        url (str): The URL to extract the domain from.

    Returns:
        str: The extracted domain or IP address.
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
    Extracts the return path from the request's parameters or form data.

    Args:
        request: The HTTP request object.
        default (Optional[str]): Default path if none found.

    Returns:
        Optional[str]: The extracted return path, or the default.
    """

    if return_path := request.args.get('return_path'):
        return extract_path_and_args(return_path)

    if return_path := request.form.get('return_path'):
        return extract_path_and_args(return_path)

    return default



def get_return_url(return_path: str, request: Request) -> Optional[str]:
    """
    Constructs the return URL based on the request's return path.

    Args:
        return_path (str): The path to construct the URL for.
        request: The HTTP request object.

    Returns:
        Optional[str]: The constructed return URL, or None if unavailable.
    """

    scheme = request.headers.get('X-Forwarded-Proto', 'https' if request.is_secure else 'http')

    domain = urlparse(request.url).netloc
    return urljoin(scheme + '://' + domain, return_path)


def get_path_from_url(url: str) -> Optional[str]:
    """
    Extracts the path component from a URL.

    Args:
        url (str): The URL to extract the path from.

    Returns:
        Optional[str]: The path, or None if the URL is invalid or has no path.
    """

    parsed_url = urlparse(url)
    return parsed_url.path if isinstance(parsed_url.path, str) else None


def remove_all_args_from_url(url: str) -> str:
    """
    Removes all query parameters from a URL.

    Args:
        url (str): The input URL.

    Returns:
        str: The URL without any query parameters.
    """

    parsed_url = urlparse(url)
    url_without_args = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                   parsed_url.params, '', parsed_url.fragment))

    return url_without_args


def add_arguments_to_html(html_content: str, request: Request, **kwargs) -> str:
    """
    Adds URL arguments to all relevant links and forms in the HTML content.

    Args:
        html_content (str): The HTML content of the page.
        request (Request): The request object containing information about the current request.
        **kwargs: Key-value pairs representing arguments to be added.

    Returns:
        str: The modified HTML content with the added arguments.
    """

    kwargs = dict_remove_type(kwargs)
    tree = lxml_html.fromstring(html_content)

    for anchor in tree.xpath("//a[@href]"):
        href = anchor.get("href")

        if "://" in href:
            anchor_host = get_domain_from_url(href)
            if anchor_host != get_domain_from_url(request.url):
                continue

        elif not href.startswith(("/", "#", "?", "&")):
            continue

        for arg, content in kwargs.items():
            if arg == "template" or url_has_argument(href, arg):
                continue

            special_character = "?" if "?" not in href else "&"
            anchor.set("href", f"{href}{special_character}{arg}={quote(content)}")

    for form in tree.xpath("//form"):
        action = form.get("action", "")

        if action:
            for arg, content in kwargs.items():
                if not url_has_argument(action, arg):
                    special_character = "?" if "?" not in action else "&"
                    form.set("action", f"{action}{special_character}{arg}={quote(content)}")

        existing_names = {input_tag.get("name") for input_tag in form.xpath(".//input[@name]")}
        for arg, content in kwargs.items():
            if arg not in existing_names:
                hidden_input = lxml_html.Element("input", type="hidden", name=arg, value=content)
                form.append(hidden_input)

    html_with_args = lxml_html.tostring(tree, encoding="unicode")
    return html_with_args
