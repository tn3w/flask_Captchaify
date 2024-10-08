"""
-~- Embeds for Captchaify -~-
This module generates the embeds that are supposed to be added
to the HTML document. It supports Google reCaptcha, hCaptcha, 
Cloudflare Turnstile, Friendly Captcha, Altcha and TrueClick.
It is part of the flask_Captchaify module for Flask applications at
https://github.com/tn3w/flask_Captchaify.

The original GPL-3.0 licence applies.
"""

import html
import json
from typing import Tuple, Optional
from .altcha import Altcha


CLASS_NAMES = {
    'recaptcha': 'g-recaptcha',
    'hcaptcha': 'h-captcha',
    'turnstile': 'cf-turnstile',
    'friendly': 'frc-captcha'
}
SCRIPT_URLS = {
    'recaptcha': 'https://www.google.com/recaptcha/api.js',
    'hcaptcha': 'https://hcaptcha.com/1/api.js',
    'turnstile': 'https://challenges.cloudflare.com/turnstile/v0/api.js',
    'friendly': 'https://cdn.jsdelivr.net/npm/friendly-challenge/widget.module.min.js',
}

EMBED = ('''<div id="TYPEBox" class="CLASS" data-sitekey="SITEKEY" data-lang="LANGUAGE" data-lan'''
         '''guage="LANGUAGE" data-theme="THEME"></div><script>SCRIPT</script>''')
SCRIPT = ('''function a(){return window.matchMedia("(prefers-color-scheme: dark)").matches?"dark'''
          '''":"light"}window.onload=function(){const t=a(),e=document.getElementById("TYPEBox")'''
          ''';null===e.getAttribute("data-theme")&&(e.setAttribute("data-theme",t),e.classList.a'''
          '''dd(t));const c=document.createElement("script");c.src="URL",c.async=!0,c.defer=!0,d'''
          '''ocument.head.appendChild(c)};''')

ALTCHA_EMBED = ('''<altcha-widget style="font-family: Segoe UI, Arial, sans-serif;" hidelogo cha'''
                '''llengejson="CHALLENGE" strings="STRINGS"></altcha-widget><script>SCRIPT</scri'''
                '''pt>''')
ALTCHA_SCRIPT = ('''function a(e){var t=document.createElement("style");t.styleSheet?t.styleShee'''
                 '''t.cssText=e:t.appendChild(document.createTextNode(e)),document.head.appendCh'''
                 '''ild(t)}const cssStringLight=":root{--altcha-color-base:#f2f2f2;--altcha-colo'''
                 '''r-text:#181818;--altcha-color-border:rgba(0, 0, 0, 0.5);--altcha-color-borde'''
                 '''r-focus:rgba(0, 0, 0, 0.5);--altcha-color-footer-bg:#f2f2f2}",cssStringDark='''
                 '''":root{--altcha-color-base:#121212;--altcha-color-text:#f2f2f2;--altcha-colo'''
                 '''r-border:rgba(255, 255, 255, 0.1);--altcha-color-border-focus:rgba(255, 255,'''
                 ''' 255, 0.1);--altcha-color-footer-bg:#1212",cssString=":root{--altcha-color-b'''
                 '''ase:#f2f2f2;--altcha-color-text:#181818;--altcha-color-border:rgba(0, 0, 0, '''
                 '''0.5);--altcha-color-border-focus:rgba(0, 0, 0, 0.5);--altcha-color-footer-bg'''
                 ''':#f2f2f2}@media (prefers-color-scheme:dark){:root{--altcha-color-base:#12121'''
                 '''2;--altcha-color-text:#f2f2f2;--altcha-color-border:rgba(255, 255, 255, 0.1)'''
                 ''';--altcha-color-border-focus:rgba(255, 255, 255, 0.1);--altcha-color-footer-'''
                 '''bg:#121212}}";window.onload=function(){const e="THEME";""!==e?a("dark"===e?c'''
                 '''ssStringDark:cssStringLight):a(cssString);const t=document.createElement("sc'''
                 '''ript");t.src="https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js",t.asyn'''
                 '''c=!0,t.defer=!0,t.type="module";document.head.appendChild(t)};''')

TRUECLICK_EMBED = ('''<div class="trueclick" data-lang="LANGUAGE" data-theme="THEME"></div><scri'''
                   '''pt>var e=document.createElement("script");e.src="/trueclick_captchaify.js"'''
                   ''',document.head.appendChild(e)</script>''')


def replace_dict(text: str, keys_and_values: dict) -> str:
    """
    Replaces each key in the text with the corresponding value.
    """

    for key, value in keys_and_values.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue

        text = text.replace(key, value)

    return text


class CaptchaEmbed:
    """
    Generates the embed that is supposed to be added to the HTML document.
    """


    def __init__(self, language: str = 'en', theme: Tuple[str, bool]\
                 = ('light', False), altcha: Altcha = None) -> None:
        """
        Initializes the CaptchaEmbed object.

        :param language: The language of the captcha.
        :param theme: The theme of the captcha.
        :param altcha: The altcha object.
        """

        self.language = language
        self.theme, self.is_default_theme = theme
        self.altcha = altcha


    def get_script(self, captcha_type: str) -> str:
        """
        Returns the script that is supposed to be added to the head of the HTML document.

        :param captcha_type: The type of captcha.
        :return: The script that is supposed to be added to the head of the HTML document.
        """

        if captcha_type == 'altcha':
            theme = self.theme if not self.is_default_theme else ''

            return ALTCHA_SCRIPT.replace('THEME', theme)

        return replace_dict(SCRIPT, {
            'TYPE': captcha_type,
            'URL': SCRIPT_URLS[captcha_type] + '?explicit=1&hl=' + self.language
        })


    def get_embed(self, captcha_type: str, site_key:\
                  Optional[str] = None, hardness: int = 2) -> str:
        """
        Returns the embed that is supposed to be added to the HTML document.

        :param captcha_type: The type of captcha.
        :param site_key: The site key of the captcha.
        :param hardness: The hardness of the Altcha captcha.
        :return: The embed that is supposed to be added to the HTML document.
        """

        if captcha_type == 'trueclick':
            return replace_dict(EMBED, {
                'LANGUAGE': self.language,
                'data-theme="THEME"' if self.is_default_theme else 'THEME':
                '' if self.is_default_theme else self.theme
            })

        if captcha_type == 'altcha':
            challenge = html.escape(json.dumps(self.altcha.create_challenge(hardness)))
            strings = html.escape(json.dumps(self.altcha.localized_text(self.language)))

            return replace_dict(
                ALTCHA_EMBED,
                {
                    'CHALLENGE': challenge,
                    'STRINGS': strings,
                    'SCRIPT': self.get_script(captcha_type)
                }
            )

        lang = 'language' if captcha_type == 'friendly' else 'lang'

        replaces = {
            'TYPE': captcha_type,
            'CLASS': CLASS_NAMES[captcha_type],
            'SITEKEY': site_key,
            'SCRIPT': self.get_script(captcha_type),
            'data-' + lang + '="LANGUAGE"': '',
            'LANGUAGE': self.language,
            'data-theme="THEME"' if self.is_default_theme else 'THEME':
            '' if self.is_default_theme else self.theme
        }
        return replace_dict(EMBED, replaces)
