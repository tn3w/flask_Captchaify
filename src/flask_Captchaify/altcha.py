"""
-~- Altcha -~-
This is a module for generating and verifying
challenges for altcha. It is part of the
flask_Captchaify module for Flask applications at
https://github.com/tn3w/flask_Captchaify.

The original GPL-3.0 licence applies.
"""

import hmac
import json
import secrets
import hashlib
from typing import Optional
from base64 import b64decode
from .webtoolbox import Translator


def secure_randrange(start: int, stop: Optional[int] = None, step: int = 1):
    """
    Generate a random number within a given range.

    :param start: The starting value of the range.
    :param stop: The ending value of the range. If not provided, `start` is treated
                 as the ending value of the range and `0` is used as the starting value.
    :param step: The step value of the range.

    :return: A random number within the specified range.
    """

    if stop is None:
        start, stop = 0, start

    if step == 0:
        raise ValueError("step argument must not be zero")

    if step < 0:
        start, stop, step = stop + 1, start + 1, -step

    if start >= stop:
        raise ValueError("empty range for randrange()")

    width = stop - start
    n = (width + step - 1) // step

    return start + step * secrets.randbelow(n)


class Altcha:
    """
    A class for generating and verifying challenges for altcha.
    """


    def __init__(self, secret: bytes) -> None:
        """
        Initialize Altcha with the secret key.

        :param secret: The secret key for generating and verifying challenges.
        """

        self.secret = secret


    def create_challenge(self, hardness: int = 1) -> dict:
        """
        Creates a challenge response for the altcha protocol.

        :param hardness: The level of difficulty of the challenge.
        :return: A dictionary containing the challenge details.
        """

        salt = secrets.token_hex(12)
        secret_number = secure_randrange(5000 * hardness, 20000 * hardness)

        challenge = hashlib.sha256((salt + str(secret_number)).encode('utf-8')).hexdigest()
        signature = hmac.new(self.secret, challenge.encode('utf-8'), hashlib.sha256).hexdigest()

        challenge = {
            'algorithm': 'SHA-256',
            'challenge': challenge,
            'salt': salt,
            'signature': signature,
        }

        return challenge


    def verify_challenge(self, challenge: str) -> bool:
        """
        Verifies a challenge response for the altcha protocol.

        :param challenge: The challenge response to verify.
        :return: True if the challenge is valid, False otherwise.
        """

        data = json.loads(b64decode(challenge))

        challenge_computed = hashlib.sha256(
            (data['salt'] + str(data['number'])).encode('utf-8')
        ).hexdigest()
        signature_computed = hmac.new(
            self.secret, data['challenge'].encode('utf-8'), hashlib.sha256
        ).hexdigest()

        return data['algorithm'] == 'SHA-256' and\
            challenge_computed == data['challenge'] and\
                signature_computed == data['signature']


    def localized_text(self, client_language: str) -> dict:
        """
        Returns the localized text for the altcha protocol.

        :param client_language: The language to use for the text.
        :return: A dictionary containing the localized text.
        """

        text = {
            "ariaLinkLabel": 'Visit Altcha.org',
            "error": 'Verification failed. Reloading page...',
            "expired": 'Verification expired. Reloading page...',
            "footer": 'Captcha by ALTCHA',
            "label": 'I am not a robot.',
            "verified": 'Verified.',
            "verifying": 'Verifying...',
            "waitAlert": 'Verifying... please wait.'
        }

        localized_text = {} if not client_language == 'en' else text
        if not client_language == 'en':
            for key, value in text.items():
                localized_text[key] = Translator().translate(value, 'en', client_language)

        localized_text['footer'] = localized_text['footer'].replace('ALTTCHA', 'ALTCHA').replace(
            'ALTCHA', ('<a href="https://altcha.org/" target="_blank" '
            f'area-label="{localized_text["ariaLinkLabel"]}" ntr="1">ALTCHA</a>')
        )

        return localized_text
