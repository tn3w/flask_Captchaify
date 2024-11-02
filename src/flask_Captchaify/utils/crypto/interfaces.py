"""
interfaces.py

This module provides interfaces for data serialization, encryption, and 
utility functions for handling byte data. The `Serialization` class defines 
methods for encoding and decoding data, while the `SymmetricEncryption` 
class outlines the structure for symmetric encryption operations. Additionally, 
utility functions are provided for splitting data into chunks of specified 
lengths, enhancing data manipulation capabilities.

License:  GNU General Public License v3.0
    https://github.com/tn3w/flask_Captchaify/blob/master/LICENSE
Source:   https://github.com/tn3w/flask_Captchaify
"""

from base64 import b85decode, b85encode
import secrets
from typing import Optional, Callable, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def split_into_chunks(data: bytes, length: int) -> list[bytes]:
    """
    Split the input data into chunks of a specified length.
    The last chunk will be removed if it is not of the given length.

    Args:
        data (bytes): The input data to be split.
        length (int, optional): The length of each chunk.

    Returns:
        list[bytes]: A list containing the chunks of the specified length.
    """

    chunks = [data[i:i+length] for i in range(0, len(data), length)]

    if len(chunks) > 0 and len(chunks[-1]) != length:
        chunks.pop()

    return chunks


class Serialization:
    """
    An interface for serialization and deserialization of data.
    """


    @staticmethod
    def encode(plain: bytes) -> str:
        """
        Encodes the given plain bytes into a string representation.

        Args:
            plain (bytes): The plain bytes to be encoded.

        Returns:
            str: The encoded string representation of the plain bytes.
        """

        return plain.decode("utf-8")


    @staticmethod
    def decode(serialized: str) -> bytes:
        """
        Decodes the given serialized string back into bytes.

        Args:
            serialized (str): The serialized string to be decoded.

        Returns:
            bytes: The decoded bytes representation of the serialized string.
        """

        return serialized.encode("utf-8")


class Hashing:
    """
    A class to perform hashing operations with optional salting and serialization.
    """


    def __init__(self, iterations: int = 100000, hash_length: int = 16, salt_length: int = 16,
                 serialization: Union[str, Callable] = "bytes") -> None:
        """
        Initializes the Hashing class with specified parameters.

        Args:
            iterations (int, optional): The number of iterations for the hashing process.
                Default is 100000.
            hash_length (int, optional): The length of the resulting hash in bytes. Default is 16.
            salt_length (int, optional): The length of the salt in bytes. Default is 16.
            serialization (Union[str, Callable], optional): The serialization method.
                Defaults to "bytes".
        """

        self.iterations = iterations
        self.hash_length = hash_length
        self.salt_length = salt_length
        self.serialization = serialization


    def _hash(self, plain_value: bytes, salt: bytes) -> bytes:
        """
        Computes the hash of the given plain value combined with the salt.

        Args:
            plain_value (bytes): The plain value to be hashed.
            salt (bytes): The salt to be combined with the plain value.

        Returns:
            bytes: The resulting hash as a byte sequence.
        """

        return plain_value + salt


    def _serialize(self, data: bytes) -> Union[str, bytes]:
        """
        Serializes the given byte data into a string format.

        Args:
            data (bytes): The byte data to be serialized.

        Returns:
            Union[str, bytes]: The serialized data representation of the byte data.
        """

        return data


    def _deserialize(self, data: Union[str, bytes]) -> bytes:
        """
        Deserializes the given data from a string format back into bytes.

        Args:
            data (Union[str, bytes]): The data to be deserialized. 
                This can be either a string or bytes.

        Returns:
            bytes: The original byte representation of the data.
        """

        if not isinstance(data, str):
            return data

        return data.encode("utf-8")


    def hash(self, plain_value: Union[str, bytes], salt: Optional[Union[str, bytes]] = None,
             return_salt: bool = False) -> Optional[
                 Union[str, bytes, Tuple[Union[str, bytes], bytes]]]:
        """
        Hashes the given plain value with an optional salt.

        Args:
            plain_value (Union[str, bytes]): The plain value to be hashed.
            salt (Optional[Union[str, bytes]]): An optional salt.
                If not provided, a new salt will be generated.
            return_salt (bool, optional): If True, returns the salt
                along with the hash. Default is False.

        Returns:
            Optional[Union[str, bytes, Tuple[Union[str, bytes], bytes]]]: 
                The serialized hash, and optionally the salt if return_salt is True.
        """

        if isinstance(plain_value, str):
            plain_value = plain_value.encode('utf-8')

        use_salt = b""
        if self.salt_length > 0:
            if salt is None:
                use_salt = secrets.token_bytes(self.salt_length)
            else:
                if isinstance(salt, str):
                    use_salt = salt.encode("utf-8")
                use_salt = use_salt[:self.salt_length]

        hashed = self._hash(plain_value, use_salt)
        combined_hash = use_salt + hashed

        serialized_hash = self._serialize(combined_hash)

        if return_salt:
            return serialized_hash, use_salt

        return serialized_hash


    def compare(self, plain_value: Union[str, bytes],
                hashed_value: Union[str, bytes], salt: Optional[Union[str, bytes]] = None) -> bool:
        """
        Compares a plain value with a hashed value to check for equality.

        Args:
            plain_value (Union[str, bytes]): The plain value to compare.
            hashed_value (Union[str, bytes]): The hashed value to compare against.
            salt (Optional[Union[str, bytes]]): An optional salt. If not provided,
                the salt will be extracted from the hashed value.

        Returns:
            bool: True if the plain value matches the hashed value, False otherwise.
        """

        if isinstance(plain_value, str):
            plain_value = plain_value.encode('utf-8')

        deserialized_hash = self._deserialize(hashed_value)

        use_salt = b""
        real_hash = hashed_value
        if self.salt_length > 0:
            if salt is not None:
                if isinstance(salt, str):
                    use_salt = salt.encode("utf-8")
                use_salt = use_salt[:self.salt_length]
            else:
                use_salt = deserialized_hash[:self.salt_length]
                real_hash = deserialized_hash[self.salt_length:]

        hashed = self._hash(plain_value, use_salt)

        return hashed == real_hash


class SymmetricEncryption:
    """
    An interface to perform symmetric encryption
    and decryption using a token-based approach.
    """


    @staticmethod
    def _hash_token(token: bytes, salt: Optional[bytes] = None,
                    length: int = 32) -> Tuple[bytes, bytes]:
        """
        Hashes the provided token using PBKDF2 with HMAC and SHA-256.

        Args:
            token (bytes): The token to be hashed.
            salt (Optional[bytes]): An optional salt. If not provided, a new salt will be generated.
            length (int): The desired length of the derived key in bytes. Default is 32 bytes.

        Returns:
            Tuple[bytes, bytes]: A tuple containing the salt and the hashed token.
        """

        if salt is None:
            salt = secrets.token_bytes(16)

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        hashed_token = kdf_.derive(token)
        return salt, hashed_token


    def __init__(self, token: Union[str, bytes], iterations: int = 1,
                 serialization: Union[str, Callable] = "base85") -> None:
        """
        Initializes the SymmetricEncryption class with a token and serialization method.

        Args:
            token (Union[str, bytes]): The token used for encryption and decryption.
            iterations (int, optional): The number of iterations for the encryption process.
            serialization (Union[str, Callable], optional): The serialization method.
                Defaults to "base85".
        """

        if isinstance(token, str):
            token = token.encode("utf-8")

        self.token = token
        self.iterations = iterations
        self.serialization = serialization


    @property
    def iv_length(self) -> int:
        """
        Returns the length of the initialization
        vector (IV) used in the encryption process.

        Returns:
            int: The length of the initialization vector in bytes.
        """

        return 16


    @property
    def key_size(self) -> int:
        """
        Get the size of the key in bytes.

        Returns:
            int: The size of the key in bytes.
        """

        return 32


    def _encrypt(self, hashed_token: bytes, plain_value: bytes) -> Tuple[Optional[bytes], bytes]:
        """
        Encrypts the given plain value using the hashed token.

        Args:
            hashed_token (bytes): The hashed token used for encryption.
            plain_value (bytes): The plain value to be encrypted.

        Returns:
            Tuple[Optional[bytes], bytes]: A tuple containing the initialization
                vector (if applicable) and the encrypted value.
        """

        return hashed_token, plain_value


    def _decrypt(self, hashed_token: bytes, cipher_value: bytes, iv: bytes) -> bytes:
        """
        Decrypts the given cipher value using the hashed token and initialization vector.

        Args:
            hashed_token (bytes): The hashed token used for decryption.
            cipher_value (bytes): The encrypted value to be decrypted.
            iv (bytes): The initialization vector used for decryption.

        Returns:
            bytes: The decrypted plain value.
        """

        return hashed_token + cipher_value + iv


    def _serialize(self, data: bytes) -> Union[str, bytes]:
        """
        Serializes the given byte data into a string format.

        Args:
            data (bytes): The byte data to be serialized.

        Returns:
            Union[str, bytes]: The serialized data representation of the byte data.
        """

        return data


    def _deserialize(self, data: Union[str, bytes]) -> bytes:
        """
        Deserializes the given data from a string format back into bytes.

        Args:
            data (Union[str, bytes]): The data to be deserialized. 
                This can be either a string or bytes.

        Returns:
            bytes: The original byte representation of the data.
        """

        if not isinstance(data, str):
            return data

        return data.encode("utf-8")


    def encrypt(self, plain_value: Union[str, bytes]) -> Union[str, bytes]:
        """
        Encrypts the given plain value.

        Args:
            plain_value (Union[str, bytes]): The plain value to be encrypted.

        Returns:
            Union[str, bytes]: The encrypted value, potentially serialized.
        """

        if isinstance(plain_value, str):
            plain_value = plain_value.encode("utf-8")

        if isinstance(plain_value, bytes):
            try:
                _ = plain_value.decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                pass
            else:
                plain_value = b85encode(plain_value)

        salt, hashed_token = self._hash_token(self.token, length = self.key_size)
        cipher_value = plain_value
        ivs = b""

        for _ in range(self.iterations):
            iv, cipher_value = self._encrypt(hashed_token, cipher_value)

            if iv is not None:
                ivs += iv

        return_data = salt + ivs + cipher_value
        return self._serialize(return_data)


    def decrypt(self, cipher_value: Union[str, bytes]) -> Union[str, bytes]:
        """
        Decrypts the given cipher value.

        Args:
            cipher_value (Union[str, bytes]): The encrypted value to be decrypted.

        Returns:
            Union[str, bytes]: The decrypted plain value, potentially deserialized.
        """

        cipher_value = self._deserialize(cipher_value)

        ivs = [b""]
        salt = cipher_value[:self.iv_length]

        if self.iv_length != 0:
            iv_length = self.iterations * self.iv_length + self.iv_length

            iv = cipher_value[self.iv_length:iv_length]
            ivs = split_into_chunks(iv, self.iv_length)

            cipher_value = cipher_value[iv_length:]
        else:
            cipher_value = cipher_value[16:]

        _, hashed_token = self._hash_token(self.token, salt, length = self.key_size)

        plain_value = cipher_value
        for current_iv in reversed(ivs):
            plain_value = self._decrypt(hashed_token, plain_value, current_iv)

        try:
            plain_value = b85decode(plain_value)
        except (UnicodeDecodeError, ValueError):
            pass

        return plain_value


if __name__ == "__main__":
    print("interfaces.py: This file is not designed to be executed.")
