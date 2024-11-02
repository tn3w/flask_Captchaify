"""
serialization.py

This module provides various serialization algorithms for encoding and decoding data 
using different formats, including Hexadecimal, UTF-8, Base85, Base64, Base32, and 
Base16. Each serialization format is encapsulated in its own class, which implements 
methods for encoding raw byte data into a string representation and decoding the 
string back into bytes. The `load_serialization` function allows for dynamic loading
of the appropriate serialization class based on a provided string identifier,
normalizing the input to match the available serialization types.

License:  GNU General Public License v3.0
    https://github.com/tn3w/flask_Captchaify/blob/master/LICENSE
Source:   https://github.com/tn3w/flask_Captchaify
"""

import re
from base64 import (
    b85encode, b85decode, b64encode,
    b64decode, b32encode, b32decode,
    b16encode, b16decode,

    standard_b64encode, standard_b64decode,
    urlsafe_b64encode, urlsafe_b64decode,
    b32hexencode, b32hexdecode
)
from urllib.parse import quote, unquote
from typing import Optional, Final, Callable

try:
    from utils.crypto.interfaces import Serialization
except ImportError:
    try:
        from src.flask_Captchaify.utils.crypto.interfaces import Serialization
    except ImportError:
        try:
            from crypto.interfaces import Serialization
        except ImportError:
            from interfaces import Serialization


class Hex(Serialization):
    """
    A class for encoding and decoding data using Hexadecimal.
    """


    @staticmethod
    def encode(plain: bytes) -> str:
        return plain.hex()


    @staticmethod
    def decode(serialized: str) -> bytes:
        return bytes.fromhex(serialized)


class UTF8(Serialization):
    """
    A class for encoding and decoding data using UTF-8.
    """


    @staticmethod
    def encode(plain: bytes) -> str:
        return plain.decode("utf-8")


    @staticmethod
    def decode(serialized: str) -> bytes:
        return serialized.encode("utf-8")


class Base85(Serialization):
    """
    A class for encoding and decoding data using Base85.
    """


    @staticmethod
    def encode(plain: bytes) -> str:
        serialized_plain = b85encode(plain)
        return serialized_plain.decode("utf-8")


    @staticmethod
    def decode(serialized: str) -> bytes:
        return b85decode(serialized)


class Base85Urlsafe(Serialization):
    """
    A class for encoding and decoding data using urlsafe Base85.
    """


    @staticmethod
    def encode(plain: bytes) -> str:
        serialized_plain = b85encode(plain)
        urlsafe_plain = quote(serialized_plain)
        return urlsafe_plain


    @staticmethod
    def decode(serialized: str) -> bytes:
        urlunsafe_plain = unquote(serialized)
        return b85decode(urlunsafe_plain)


class Base64(Serialization):
    """
    A class for encoding and decoding data using Base64.
    """


    @staticmethod
    def encode(plain: bytes) -> str:
        serialized_plain = b64encode(plain)
        serialized_plain_str = serialized_plain.decode('utf-8')

        return serialized_plain_str.rstrip("=")


    @staticmethod
    def decode(serialized: str) -> bytes:
        required_padding = (4 - len(serialized) % 4) % 4
        serialized +='=' * required_padding

        return b64decode(serialized)


class Base64Standard(Serialization):
    """
    A class for encoding and decoding data using standard Base64.
    """


    @staticmethod
    def encode(plain: bytes) -> str:
        serialized_plain = standard_b64encode(plain)
        serialized_plain_str = serialized_plain.decode('utf-8')

        return serialized_plain_str.rstrip("=")


    @staticmethod
    def decode(serialized: str) -> bytes:
        required_padding = (4 - len(serialized) % 4) % 4
        serialized +='=' * required_padding

        return standard_b64decode(serialized)


class Base64UrlSafe(Serialization):
    """
    A class for encoding and decoding data using urlsafe Base64.
    """


    @staticmethod
    def encode(plain: bytes) -> str:
        serialized_plain = urlsafe_b64encode(plain)
        serialized_plain_str = serialized_plain.decode('utf-8')

        return serialized_plain_str.rstrip("=")


    @staticmethod
    def decode(serialized: str) -> bytes:
        required_padding = (4 - len(serialized) % 4) % 4
        serialized +='=' * required_padding

        return urlsafe_b64decode(serialized)


class Base62(Serialization):
    """
    A class for encoding and decoding data using Base62 encoding.
    """


    BASE62_CHARACTERS: Final[str] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


    @staticmethod
    def encode(plain: bytes) -> str:
        base = len(Base62.BASE62_CHARACTERS)
        number = int.from_bytes(plain, byteorder='big')
        encoded = []

        while number > 0:
            number, remains = divmod(number, base)
            encoded.append(Base62.BASE62_CHARACTERS[remains])

        return ''.join(reversed(encoded))


    @staticmethod
    def decode(serialized: str) -> bytes:
        base = len(Base62.BASE62_CHARACTERS)

        char_to_value = {char: index for index, char in enumerate(Base62.BASE62_CHARACTERS)}

        num = 0
        for char in serialized:
            if char not in char_to_value:
                raise ValueError(f"Invalid character '{char}' in input.")

            num = num * base + char_to_value[char]

        byte_length = (num.bit_length() + 7) // 8 or 1
        return num.to_bytes(byte_length, byteorder='big')


class Base32(Serialization):
    """
    A class for encoding and decoding data using Base32.
    """


    @staticmethod
    def encode(plain: bytes) -> str:
        return b32encode(plain).decode('utf-8')


    @staticmethod
    def decode(serialized: str) -> bytes:
        return b32decode(serialized)


class Base32Hex(Serialization):
    """
    A class for encoding and decoding data using Base32Hex.
    """


    @staticmethod
    def encode(plain: bytes) -> str:
        return b32hexencode(plain).decode('utf-8')


    @staticmethod
    def decode(serialized: str) -> bytes:
        return b32hexdecode(serialized)


class Base16(Serialization):
    """
    A class for encoding and decoding data using Base16 (Hex).
    """


    @staticmethod
    def encode(plain: bytes) -> str:
        return b16encode(plain).decode('utf-8')


    @staticmethod
    def decode(serialized: str) -> bytes:
        return b16decode(serialized)


SERIALIZATION_TYPES: Final[dict[str, Callable]] = {
    "hex": Hex, "utf8": UTF8, "base85": Base85,
    "base85urlsafe": Base85Urlsafe, "urlsafebase85": Base85Urlsafe,
    "base64": Base64, "base64standard": Base64Standard,
    "standardbase64": Base64Standard, "base64urlsafe": Base64UrlSafe,
    "urlsafebase64": Base64UrlSafe, "base62": Base62,
    "base32": Base32, "base32hex": Base32Hex,
    "hexbase32": Base32Hex, "base16": Base16
}


def load_serialization(serialization_type: str) -> Optional[Callable]:
    """
    Load the appropriate serialization class based on the provided serialization type.

    Args:
        serialization_type (str): A string representing the desired serialization type.
                                  This can include variations of the type name, which will
                                  be normalized to match the keys in the SERIALIZATION_TYPES
                                  dictionary.

    Returns:
        Optional[Callable]: The corresponding serialization class if found, or None if
                            the serialization type is not recognized.
    """

    normalized_type = re.sub(r'[^a-zA-Z0-9]', '', serialization_type)

    return SERIALIZATION_TYPES.get(normalized_type, None)


if __name__ == "__main__":
    print("serilization.py: This file is not designed to be executed.")
