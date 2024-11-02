"""
symmetric.py

This module provides interfaces and implementations for various symmetric 
encryption algorithms, including AES, Camellia, SM4, and ChaCha20. The 
`SerializedSymmetricEncryption` class serves as a base for symmetric 
encryption that supports serialization and deserialization of data. 
Each algorithm class implements the necessary methods for encryption and 
decryption, utilizing secure padding and initialization vectors.

License:  GNU General Public License v3.0
    https://github.com/tn3w/flask_Captchaify/blob/master/LICENSE
Source:   https://github.com/tn3w/flask_Captchaify
"""

import uuid
import secrets
import hashlib
import platform
from typing import Union, Callable, Tuple, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    from utils.crypto.serialization import load_serialization, Base85
    from utils.crypto.interfaces import SymmetricEncryption, Serialization
except ImportError:
    try:
        from src.flask_Captchaify.utils.crypto.serialization import load_serialization, Base85
        from src.flask_Captchaify.utils.crypto.interfaces import SymmetricEncryption, Serialization
    except ImportError:
        try:
            from crypto.serialization import load_serialization, Base85
            from crypto.interfaces import SymmetricEncryption, Serialization
        except ImportError:
            from serialization import load_serialization, Base85
            from interfaces import SymmetricEncryption, Serialization


def generate_unique_key(serialization: Union[Callable, str] = "base85") -> str:
    """
    Generate a unique key based on system information and a specified serialization method.

    Args:
        serialization (Union[Callable, str]): The serialization method to use. 
            Can be a callable or a string indicating the serialization type (default is "base85").

    Returns:
        str: A unique key generated from the system information
             and serialized using the specified method.
    """

    serialize = load_serialization(serialization) # type: ignore
    if not isinstance(serialization, Callable):
        serialize = Base85()

    system_info = {
        "node": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "mac_address": get_mac_address()
    }

    info_string = "".join(f"{key}:{value}|" for key, value in system_info.items() if value)

    serialize: Serialization
    unique_key = serialize.encode(hashlib.sha512(info_string.encode()).digest())

    return unique_key


def get_mac_address() -> Optional[str]:
    """
    Retrieve the MAC address of the current machine.

    Returns:
        Optional[str]: The MAC address as a string in the format "xx:xx:xx:xx:xx:xx", 
        or None if the MAC address could not be retrieved.
    """

    mac = None
    try:
        mac = ":".join([
            f"{(uuid.getnode() >> elements) & 0xff:02x}"
            for elements in range(0, 2 * 6, 2)
        ][::-1])
    except Exception:
        pass

    if not isinstance(mac, str) or len(mac) != 17:
        return None

    return mac


class SerializedSymmetricEncryption(SymmetricEncryption):
    """
    A interface for symmetric encryption that supports
    serialization and deserialization of data.
    """


    def _load_serialization(self) -> Optional[Callable]:
        serialization = self.serialization

        if isinstance(serialization, str):
            serialization = load_serialization(serialization)

        if not isinstance(serialization, Callable):
            return None

        return serialization


    def _serialize(self, data: bytes) -> Union[str, bytes]:
        serialization = self._load_serialization() # type: ignore
        if serialization is None:
            return data

        serialization: Serialization
        return serialization.encode(data)


    def _deserialize(self, data: Union[str, bytes]) -> bytes:
        if not isinstance(data, str):
            return data

        serialization = self._load_serialization() # type: ignore
        if serialization is None:
            return data.encode("utf-8", errors = "ignore")

        serialization: Serialization
        return serialization.decode(data)


class AlgorythmInterface(SerializedSymmetricEncryption):
    """
    A class that implements an symmetric algorythm interface for
    encryption and decryption with support for multiple rounds of encryption.
    """


    @property
    def algorythm(self) -> Callable:
        """
        Retrieve the encryption algorithm used by this class.

        Returns:
            Callable: The AES encryption algorithm callable from the `algorithms` module.
        """

        return algorithms.AES


    def _encrypt(self, hashed_token: bytes, plain_value: bytes) -> Tuple[Optional[bytes], bytes]:
        iv = secrets.token_bytes(self.iv_length)

        cipher = Cipher(self.algorythm(hashed_token), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(self.algorythm.block_size).padder() # type: ignore
        padded_data = padder.update(plain_value) + padder.finalize()

        cipher_value = encryptor.update(padded_data) + encryptor.finalize()

        return iv, cipher_value


    def _decrypt(self, hashed_token: bytes, cipher_value: bytes, iv: bytes) -> bytes:
        cipher = Cipher(
            self.algorythm(hashed_token),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(cipher_value) + decryptor.finalize()

        unpadder = padding.PKCS7(self.algorythm.block_size).unpadder() # type: ignore
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return decrypted_data


class AES(AlgorythmInterface):
    """
    A class that implements AES (Advanced Encryption Standard)
    encryption and decryption with support for multiple rounds of encryption.
    """


    @property
    def algorythm(self) -> Callable:
        return algorithms.AES


class AES256(AES):
    """
    A class that implements AES-256 encryption and decryption
    with support for multiple rounds of encryption.
    """


    @property
    def algorythm(self) -> Callable:
        return algorithms.AES256


class AES128(AlgorythmInterface):
    """
    A class that implements AES-128 encryption and decryption
    with support for multiple rounds of encryption.
    """


    @property
    def key_size(self) -> int:
        return 16


    @property
    def algorythm(self) -> Callable:
        return algorithms.AES128


class Camellia(AlgorythmInterface):
    """
    A class that implements Camellia encryption and decryption
    with support for multiple rounds of encryption.
    """


    @property
    def iv_length(self) -> int:
        return 16


    @property
    def key_size(self) -> int:
        return 32


    @property
    def algorythm(self) -> Callable:
        return algorithms.Camellia


class SM4(AlgorythmInterface):
    """
    A class that implements SM4 encryption and decryption
    with support for multiple rounds of encryption.
    """


    @property
    def iv_length(self) -> int:
        return 16


    @property
    def key_size(self) -> int:
        return 16


    @property
    def algorythm(self) -> Callable:
        return algorithms.SM4


class ChaCha20(SerializedSymmetricEncryption):
    """
    A class that implements ChaCha20 encryption and decryption
    with support for multiple rounds of encryption.
    """


    @property
    def iv_length(self) -> int:
        return 16


    @property
    def key_size(self) -> int:
        return 32


    def _encrypt(self, hashed_token: bytes, plain_value: bytes) -> Tuple[Optional[bytes], bytes]:
        iv = secrets.token_bytes(self.iv_length)

        cipher = Cipher(
            algorithms.ChaCha20(hashed_token, iv),
            mode=None, backend=default_backend()
        )
        encryptor = cipher.encryptor()

        cipher_value = encryptor.update(plain_value) + encryptor.finalize()
        return iv, cipher_value


    def _decrypt(self, hashed_token: bytes, cipher_value: bytes, iv: bytes) -> bytes:
        cipher = Cipher(
            algorithms.ChaCha20(hashed_token, iv),
            mode=None, backend=default_backend()
        )
        decryptor = cipher.decryptor()

        plain_value = decryptor.update(cipher_value) + decryptor.finalize()
        return plain_value


if __name__ == "__main__":
    print("symmetric.py: This file is not designed to be executed.")
