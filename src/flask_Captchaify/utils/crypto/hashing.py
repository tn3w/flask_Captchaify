"""
hashing.py

This module implements various cryptographic hashing algorithms, including MD5 and 
SHA family algorithms (SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512). Each algorithm 
is encapsulated in its own class, providing methods for hashing data and supporting 
serialization and deserialization of the hashed data. The `SerializedHashing` class 
serves as a base class, offering common functionality for handling serialization, while 
the `AlgorythmInterface` class defines a structure for key derivation functions (KDF) 
using specified hashing algorithms.

License:  GNU General Public License v3.0
    https://github.com/tn3w/flask_Captchaify/blob/master/LICENSE
Source:   https://github.com/tn3w/flask_Captchaify
"""

from typing import Union, Callable, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import MD5 as md5
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from utils.crypto.serialization import load_serialization
    from utils.crypto.interfaces import Serialization, Hashing
except ImportError:
    try:
        from src.flask_Captchaify.utils.crypto.serialization import load_serialization
        from src.flask_Captchaify.utils.crypto.interfaces import Serialization, Hashing
    except ImportError:
        try:
            from crypto.serialization import load_serialization
            from crypto.interfaces import Serialization, Hashing
        except ImportError:
            from serialization import load_serialization
            from interfaces import Serialization, Hashing


class SerializedHashing(Hashing):
    """
    A interface for hashing that supports
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


class MD5(SerializedHashing):
    """
    Implements the MD5 hashing algorithm.

    For more information, refer to RFC 1321: 
    https://datatracker.ietf.org/doc/html/rfc1321
    """


    def __init__(self, hash_length: int = 16,
                 salt_length: int = 16,
                 serialization: Union[str, Callable] = "bytes") -> None:
        """
        Initializes the Hashing class with specified parameters.

        Args:
            hash_length (int, optional): The length of the resulting hash in bytes. Default is 16.
            salt_length (int, optional): The length of the salt in bytes. Default is 16.
            serialization (Union[str, Callable], optional): The serialization method.
                Defaults to "bytes".
        """

        super().__init__(1, hash_length, salt_length, serialization)


    def _hash(self, plain_value: bytes, salt: bytes) -> bytes:
        digest = hashes.Hash(md5(), backend=default_backend())
        digest.update(salt + plain_value)
        hashed_bytes = digest.finalize()

        return hashed_bytes


class AlgorythmInterface(SerializedHashing):
    """
    An interface for hashing that utilizes a key derivation function (KDF) 
    with a specified hashing algorithm.
    """


    @property
    def algorythm(self) -> hashes.HashAlgorithm:
        """
        Gets the hashing algorithm used for deriving the hash.

        Returns:
            hashes.HashAlgorithm: The hashing algorithm instance.
        """

        return hashes.SHA3_512()


    def _hash(self, plain_value: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm = self.algorythm,
            length = self.hash_length,
            salt = salt,
            iterations = self.iterations,
            backend = default_backend()
        )

        hashed_value = kdf.derive(plain_value)

        return hashed_value


class SHA1(AlgorythmInterface):
    """
    Implements the SHA-1 hashing algorithm.

    For more information, refer to RFC 6234:
    https://datatracker.ietf.org/doc/html/rfc6234
    """

    @property
    def algorythm(self) -> hashes.HashAlgorithm:
        return hashes.SHA1()


class SHA224(AlgorythmInterface):
    """
    Implements the SHA-224 hashing algorithm.

    For more information, refer to RFC 6234:
    https://datatracker.ietf.org/doc/html/rfc6234
    """


    @property
    def algorythm(self) -> hashes.HashAlgorithm:
        return hashes.SHA3_224()


class SHA256(AlgorythmInterface):
    """
    Implements the SHA-256 hashing algorithm.

    For more information, refer to RFC 6234:
    https://datatracker.ietf.org/doc/html/rfc6234
    """


    @property
    def algorythm(self) -> hashes.HashAlgorithm:
        return hashes.SHA3_256()


class SHA384(AlgorythmInterface):
    """
    Implements the SHA-384 hashing algorithm.

    For more information, refer to RFC 6234:
    https://datatracker.ietf.org/doc/html/rfc6234
    """


    @property
    def algorythm(self) -> hashes.HashAlgorithm:
        return hashes.SHA3_384()


class SHA512(AlgorythmInterface):
    """
    Implements the SHA-512 hashing algorithm.

    For more information, refer to RFC 6234:
    https://datatracker.ietf.org/doc/html/rfc6234
    """


    @property
    def algorythm(self) -> hashes.HashAlgorithm:
        return hashes.SHA3_512()


if __name__ == "__main__":
    print("hashing.py: This file is not designed to be executed.")
