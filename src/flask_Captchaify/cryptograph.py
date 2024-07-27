"""
-~- Cryptograph -~-
Cryptograph is a library that implements cryptography for the efficient
storage of data in encrypted or hashed form. It also includes
Cache and TimeStorage tools. It is part of the flask_Captchaify module
for Flask applications at https://github.com/tn3w/flask_Captchaify.

The original GPL-3.0 licence applies.
"""

import os
import re
import time
import json
import pickle
import secrets
from typing import Optional, Union, Tuple
from binascii import Error as BinasciiError
from base64 import urlsafe_b64encode, urlsafe_b64decode, b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .utils import DATA_DIR, PICKLE, handle_exception


class SymmetricEncryption:
    """
    Implementation of symmetric encryption with AES
    """

    def __init__(self, password: Optional[Union[str, bytes]] = None,\
                 salt_length: int = 32, use_salt: bool = True,
                 salt: Optional[bytes] = None, debug: bool = False) -> None:
        """
        Initialize symmetric encryption.

        :param password: A secure encryption password, should be at least 32 characters long.
        :param salt_length: The length of the salt, should be at least 16.
        :param use_salt: Whether to use a salt in the encryption process.
        :param salt: The salt to use in the encryption process.
        :param debug: Whether to throw error messages directly.
        """

        if password is None:
            password = secrets.token_bytes(64)

        if not isinstance(password, bytes):
            password = password.encode('utf-8')

        self.password = password
        self.salt_length = salt_length
        self.use_salt = use_salt or isinstance(salt, bytes)
        self.salt = salt
        self.debug = debug


    def encrypt(self, plain_value: Union[str], return_as_bytes:\
                bool = False, url_safe: bool = True) -> Optional[str]:
        """
        Encrypts a value.

        :param plain_value: The value to be encrypted.
        :param hash_password: Whether to hash the password.
        :param return_as_bytes: Whether to return the result as bytes.
        :param url_safe: Whether to return the result as a URL-safe string.
        """

        try:
            if not isinstance(plain_value, bytes):
                plain_value = plain_value.encode('utf-8')

            salt = b''
            if self.use_salt:
                if isinstance(self.salt, bytes):
                    salt = self.salt
                else:
                    salt = secrets.token_bytes(self.salt_length)

            kdf_ = PBKDF2HMAC(
                algorithm = hashes.SHA256(),
                length = 32,
                salt = salt,
                iterations = 20000,
                backend = default_backend()
            )
            key = kdf_.derive(self.password)

            iv = secrets.token_bytes(16)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plain_value) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            encrypted_bytes = iv + ciphertext

            if self.use_salt and not isinstance(self.salt, bytes):
                encrypted_bytes = salt + encrypted_bytes

            if return_as_bytes:
                return encrypted_bytes

            b64 = urlsafe_b64encode if url_safe else b64encode
            return b64(encrypted_bytes).decode('utf-8').rstrip('=')
        except Exception as exc:
            if self.debug:
                handle_exception(exc, False, False)

        return None


    def decrypt(self, cipher_text: Union[str, bytes]) -> Optional[str]:
        """
        Decrypts a text

        :param ciphertext: The encrypted text
        """

        try:
            encrypted_value = None
            if isinstance(cipher_text, str):
                is_urlsafe = re.match(r'^[A-Za-z0-9\-_]+={0,2}$', cipher_text)

                no_urlsafe = False
                for i1 in range(2):
                    if i1 >= 1:
                        cipher_text = cipher_text.rstrip('=')

                    for i2 in range(4):
                        try:
                            b64 = urlsafe_b64decode if is_urlsafe and not no_urlsafe else b64decode
                            encrypted_value = b64(cipher_text.encode('utf-8'))
                        except BinasciiError:
                            cipher_text += '='
                        else:
                            break

                        if i2 >= 3:
                            if is_urlsafe or no_urlsafe:
                                return None

                            no_urlsafe = True

            elif isinstance(cipher_text, bytes):
                encrypted_value = cipher_text

            if encrypted_value is None:
                return None

            if self.use_salt:
                if isinstance(self.salt, bytes):
                    iv, cipher_text = encrypted_value[:16], encrypted_value[16:]
                    salt = self.salt
                else:
                    salt, iv, cipher_text = encrypted_value[:self.salt_length],\
                        encrypted_value[self.salt_length:self.salt_length + 16],\
                            encrypted_value[self.salt_length + 16:]
            else:
                iv, cipher_text = encrypted_value[:16], encrypted_value[16:]
                salt = b''

            kdf_ = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=20000,
                backend=default_backend()
            )
            key = kdf_.derive(self.password)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
            plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

            try:
                return plaintext.decode()
            except UnicodeDecodeError:
                return plaintext
        except Exception as exc:
            if self.debug:
                handle_exception(exc, False, False)

        return None


class Hashing:
    """
    Implementation for hashing
    """

    def __init__(self, use_salt: bool = True, salt_length:\
                 int = 16, iterations: int = 10000, debug: bool = False) -> None:
        """
        Initializes the hashing object.

        :param use_salt: If the salt should be used.
        :param salt_length: The length of the salt, should be at least 16.
        :param iterations: The number of iterations, should be at least 10000.
        :param debug: Whether to throw error messages directly.
        """

        self.use_salt = use_salt
        self.salt_length = salt_length
        self.iterations = iterations
        self.debug = debug


    def get_salt(self, hashed_value: Union[str, bytes]) -> Optional[bytes]:
        """
        Returns the salt from a hashed value.

        :param hashed_value: The hashed value.
        """

        try:
            hashed_bytes = None
            if isinstance(hashed_value, str):
                is_urlsafe = re.match(r'^[A-Za-z0-9\-_]+={0,2}$', hashed_value)

                no_urlsafe = False
                for i1 in range(2):
                    if i1 >= 1:
                        hashed_value = hashed_value.rstrip('=')

                    for i2 in range(4):
                        try:
                            if is_urlsafe and not no_urlsafe:
                                hashed_bytes = urlsafe_b64decode(hashed_value.encode('utf-8'))
                            else:
                                hashed_bytes = b64decode(hashed_value.encode('utf-8'))
                        except BinasciiError:
                            hashed_value += '='
                        else:
                            break

                        if i2 >= 3:
                            if is_urlsafe or no_urlsafe:
                                return False

                            no_urlsafe = True

            elif isinstance(hashed_value, bytes):
                hashed_bytes = hashed_value

            if hashed_bytes is None:
                return None

            if bytes([0, 0]) in hashed_bytes:
                hashed_bytes, salt = hashed_bytes.split(bytes([0, 0]))

            return salt
        except Exception as exc:
            if self.debug:
                raise exc

            handle_exception(exc, False, False)

        return None


    def hash(self, plain_value: Union[str, bytes], salt: Optional[bytes] = None,
             hash_length: int = 16, return_as_bytes: bool = False,\
                return_salt: bool = False, url_safe: bool = False) -> Optional[Union[str, bytes]]:
        """
        Function to hash a plain value.

        :param plain_value: The value to be hashed.
        :param salt: The salt, makes the hashing process more secure. (Optional)
        :param hash_length: The length of the hashed value, this is not
                            the same as the length of the returned string.
        :param return_as_bytes: Whether the hashed value should be returned
                                as bytes or a string.
        :param return_salt: Whether the salt should be returned.
        :param url_safe: Whether to return the result as a URL-safe string.
        """

        try:
            if not isinstance(plain_value, bytes):
                plain_value = plain_value.encode('utf-8')

            if not isinstance(salt, bytes):
                salt = secrets.token_bytes(self.salt_length)

            if not self.use_salt:
                salt = b''

            kdf = PBKDF2HMAC(
                algorithm = hashes.SHA3_512(),
                length = hash_length,
                salt = salt,
                iterations = self.iterations,
                backend = default_backend()
            )

            key = kdf.derive(plain_value)

            hashed_bytes = key[:hash_length] + (bytes([0, 0]) + salt if self.use_salt else b'')
            if return_as_bytes:
                if return_salt:
                    return hashed_bytes, salt

                return hashed_bytes

            b64 = urlsafe_b64encode if url_safe else b64encode
            hashed_str = b64(hashed_bytes).decode('utf-8').rstrip('=')
            if return_salt:
                return hashed_str, salt

            return hashed_str
        except Exception as exc:
            if self.debug:
                handle_exception(exc, False, False)

        return None


    def compare(self, plain_value: Union[str, bytes], hashed_value:\
                Union[str, bytes], salt: Optional[bytes] = None) -> bool:
        """
        Compares a plain value with a hashed value.

        :param plain_value: The value to be hashed.
        :param hashed_value: The hashed value.
        :param salt: The salt, should be the same as the one used in the hashing process.
        """

        try:
            if not isinstance(plain_value, bytes):
                plain_value = plain_value.encode('utf-8')

            hashed_bytes = None
            if isinstance(hashed_value, str):
                is_urlsafe = re.match(r'^[A-Za-z0-9\-_]+={0,2}$', hashed_value)

                no_urlsafe = False
                for i1 in range(2):
                    if i1 >= 1:
                        hashed_value = hashed_value.rstrip('=')

                    for i2 in range(4):
                        try:
                            b64 = urlsafe_b64decode if is_urlsafe and not no_urlsafe else b64decode
                            hashed_bytes = b64(hashed_value.encode('utf-8'))
                        except BinasciiError:
                            hashed_value += '='
                        else:
                            break

                        if i2 >= 3:
                            if is_urlsafe or no_urlsafe:
                                return False

                            no_urlsafe = True

            elif isinstance(hashed_value, bytes):
                hashed_bytes = hashed_value

            if hashed_bytes is None:
                return False

            if bytes([0, 0]) in hashed_bytes:
                hashed_bytes, salt = hashed_bytes.split(bytes([0, 0]))

            if not self.use_salt:
                salt = b''

            hash_length = len(hashed_bytes)

            kdf = PBKDF2HMAC(
                algorithm = hashes.SHA3_512(),
                length = hash_length,
                salt = salt,
                iterations = self.iterations,
                backend = default_backend()
            )

            hashed_value = kdf.derive(plain_value)[:hash_length]

            return hashed_bytes == hashed_value
        except Exception as exc:
            if self.debug:
                handle_exception(exc, False, False)

        return False


class SSES:
    """
    Space-saving encryption scheme (SSES) for encrypting data without keys and decrypting with keys.
    """

    def __init__(self, password: str, separator: str = '--',
                 with_keys: bool = False, debug: bool = False) -> None:
        """
        Initializes the SSES instance with the specified symmetric cryptography object and separator

        :param password: A secure encryption password, should be at least 32 characters long.
        :param separator: The separator string to use for joining
                          values before encryption. Defaults to '--'.
        :param with_keys: Whether the keys should also be encrypted.
        :param debug: Whether to throw error messages directly.
        """

        self.password = password
        self.separator = separator
        self.with_keys = with_keys
        self.debug = debug


    def encrypt(self, data_dict: dict) -> Optional[str]:
        """
        Encrypts the provided values.

        :param data_dict: Keyword arguments containing key-value pairs to encrypt.
        :return: The encrypted data.
        """

        try:
            if not self.with_keys:
                values = list(data_dict.values())

                new_values = []
                for value in values:
                    if isinstance(value, (list, dict)):
                        value = '§§' + b64encode(pickle.dumps(value)).decode('utf-8')
                    new_values.append(value)

                text_data = self.separator.join(new_values)
            else:
                text_data = pickle.dumps(data_dict)

            encrypted_data = SymmetricEncryption(self.password).encrypt(text_data)

            return encrypted_data
        except Exception as exc:
            if self.debug:
                handle_exception(exc, False, False)

        return None


    def decrypt(self, encrypted_data: str, dict_keys:\
                Optional[list] = None) -> Optional[Union[dict, list]]:
        """
        Decrypts the provided encrypted data.

        :param encrypted_data: The encrypted data to decrypt.
        :param dict_keys: A list of keys to use for forming a dictionary from decrypted values.
        :return: Decrypted data as either a dictionary (if dict_keys is provided) or a list.
        """

        try:
            decrypted_data = SymmetricEncryption(
                self.password, debug = self.debug
            ).decrypt(encrypted_data)

            if decrypted_data is None:
                return None

            if not self.with_keys:
                values = decrypted_data.split(self.separator)

                if not isinstance(dict_keys, list) or len(dict_keys) == 0:
                    return values

                data_dict = {}
                for i, dict_key in enumerate(dict_keys):
                    if len(values) - 1 < i:
                        break

                    value = values[i]
                    if value.startswith('§§'):
                        value = pickle.loads(b64decode(value[1:].encode('utf-8')))

                    data_dict[dict_key] = value
            else:
                data_dict = pickle.loads(decrypted_data)

            return data_dict
        except Exception as exc:
            if self.debug:
                handle_exception(exc, False, False)

        return None


class TimeStorage:
    """
    A class to store time data in a file.
    """

    def __init__(self, file_name: str, dir_path: Optional[str] = DATA_DIR,\
                 store_anonymously: bool = False, ttl: Optional[int] = 259200,
                 max_size: int = 12, debug: bool = False) -> None:
        """
        Initializes the TimeStorage object.

        :param file_name: The name of the file to store time data.
        :param dir_path: The directory path to store time data.
        :param store_anonymously: Whether to store the time data anonymously.
        :param ttl: The time to live in seconds, after that time data will be removed
                    from the file.
        :param max_size: The maximum size of the stored timestamps.
        :param debug: Whether to throw error messages directly.
        """

        if not file_name.endswith('.pkl'):
            file_name += '.pkl'

        self.file_path = os.path.join(dir_path, file_name)
        self.store_anonymously = store_anonymously
        self.ttl = ttl
        self.max_size = max_size
        self.debug = debug


    def clean_timestamps(self, data: dict) -> dict:
        """
        Removes expired time data from the file.

        :param data: The data to clean.
        :return: The cleaned data.
        """

        try:
            new_data = {}
            for key, timestamps in data.items():
                new_timestamps = []
                for timestamp in timestamps:
                    if isinstance(timestamp, int):
                        if int(time.time()) - timestamp < self.ttl:
                            new_timestamps.append(timestamp)

                if len(new_timestamps) > 0:
                    new_data[key] = new_timestamps

            return new_data
        except Exception as exc:
            if self.debug:
                handle_exception(exc, False, False)

        return {}


    def add_time(self, key: any) -> None:
        """
        Adds the current time to an key in the file.

        :param key: The key to add the time to.
        """

        try:
            data = PICKLE.load(self.file_path, {})
            if not isinstance(data, dict):
                data = {}

            found_key = None
            if self.store_anonymously:
                for hashed_key in data.keys():
                    if Hashing(debug = self.debug).compare(key, hashed_key):
                        found_key = hashed_key
                        break
            elif key in data:
                found_key = key

            data = self.clean_timestamps(data)

            if found_key is not None:
                if found_key in data:
                    data[found_key].insert(0, int(time.time()))
                    data[found_key] = data[found_key][:self.max_size + 1]
                else:
                    data[found_key] = [int(time.time())]
            else:
                store_key = Hashing(debug = self.debug).hash(key, return_as_bytes = True)\
                    if self.store_anonymously else key
                data[store_key] = [int(time.time())]

            PICKLE.dump(data, self.file_path)
        except Exception as exc:
            if self.debug:
                handle_exception(exc, False, False)


    def get_counts(self, key: any) -> Tuple[int, int]:
        """
        Gets the number of times the key has been used and the total number of
        times of any key that has been stored.

        :param key: The key to get the counts for.
        :return: The number of times the key has been used and the total number.
        """

        try:
            data = PICKLE.load(self.file_path, {})
            if not isinstance(data, dict):
                data = {}

            data = self.clean_timestamps(data)

            key_count = 0
            total_count = 0

            for hashed_key, timestamps in data.items():
                if self.store_anonymously:
                    if (self.store_anonymously and Hashing(debug = self.debug)\
                        .compare(key, hashed_key)) or key == hashed_key:
                        key_count += len(timestamps)

                total_count += len(timestamps)

            return key_count, total_count
        except Exception as exc:
            if self.debug:
                handle_exception(exc, False, False)

        return 0, 0


class Cache(dict):
    """
    A dictionary-based cache that loads and saves data to a file using pickle.
    """


    def __init__(self, file_name: str, dir_path: Optional[str] = DATA_DIR,\
                 store_anonymously: bool = False, ttl: Optional[int] = 259200,
                 debug: bool = False) -> None:
        """
        Initializes the Cache object.

        :param file_name: The name of the file to store cache data.
        :param dir_path: The directory path to store cache data.
        :param store_anonymously: Whether to store the cache data anonymously.
        :param ttl: The time to live in seconds, after that time data will be removed
                    from the cache.
        :param debug: Whether to throw error messages directly.
        """

        if not file_name.endswith('.pkl'):
            file_name += '.pkl'

        self.file_path = os.path.join(dir_path, file_name)
        self.store_anonymously = store_anonymously
        self.ttl = ttl
        self.debug = debug

        super().__init__()


    def does_exist(self, key: any) -> bool:
        """
        Checks if the given key exists in the cache.

        :param key: The key to check.
        :return: True if the key exists in the cache, False otherwise.
        """

        try:
            data = self.load()
            if self.store_anonymously:
                for hashed_key in data.keys():
                    if Hashing(debug = self.debug).compare(key, hashed_key):
                        return True

                return False

            return key in data
        except Exception as exc:
            if self.debug:
                handle_exception(exc, False, False)

        return False


    def __getitem__(self, key: any) -> any:
        """
        Retrieves the value associated with the given key from the cache.

        :param key: The key for which the value is to be retrieved.
        :return: The value associated with the key, or None if the key is not found.
        """

        data = self.load()

        try:
            item_data = None

            if not self.store_anonymously:
                item_data = data.get(key, None)

                if isinstance(item_data, tuple):
                    try:
                        item_data = item_data[0]
                    except Exception:
                        pass

                return item_data

            for key_data, value_data in data.items():
                if Hashing(debug = self.debug).compare(key, key_data):
                    hashed_key, item_data = key_data, value_data
                    break

            if item_data is None:
                return None

            if isinstance(item_data, tuple):
                item_data = item_data[0]

            salt = Hashing(debug = self.debug).get_salt(hashed_key)
            decrypted_data = SymmetricEncryption(
                key, salt = salt, debug = self.debug
            ).decrypt(item_data)

            try:
                decrypted_data = json.loads(decrypted_data)
            except Exception:
                pass

            return decrypted_data
        except Exception as exc:
            if self.debug:
                handle_exception(exc, False, False)

        return None


    def __setitem__(self, key: any, value: any) -> None:
        """
        Sets the value associated with the given key in the cache.

        :param key: The key for which the value is to be set.
        :param value: The value to be set for the key.
        """

        try:
            data = self.load()

            if not isinstance(data, dict):
                data = {}

            if self.store_anonymously:
                if isinstance(key, str):
                    hashed_key, salt = Hashing(debug = self.debug).hash(
                        key, return_as_bytes = True, return_salt = True
                    )
                else:
                    hashed_key = key

                try:
                    value = json.dumps(value)
                except Exception:
                    pass

                if isinstance(value, str):
                    value = SymmetricEncryption(
                        key, salt = salt, debug = self.debug
                    ).encrypt(value, return_as_bytes = True)
            else:
                hashed_key = key

            data[hashed_key] = (value, int(time.time()))

            self.dump(data)
        except Exception as exc:
            if self.debug:
                handle_exception(exc, is_app_error = False)


    def __delitem__(self, key: any) -> None:
        """
        Deletes the value associated with the given key from the cache.

        :param key: The key for which the value is to be deleted.
        """

        try:
            data = self.load()

            if self.store_anonymously:
                for key_data in data.keys():
                    if Hashing(debug = self.debug).compare(key, key_data):
                        key = key_data
                        break

            del data[key]

            self.dump(data)
        except Exception as exc:
            if self.debug:
                handle_exception(exc, is_app_error = False)


    def load(self) -> dict:
        """
        Loads and returns the cache data from the file.

        :return: The cache data from the file. If the cache file does not contain
                 data for this file_name, an empty dictionary is returned.
        """

        try:
            data = PICKLE.load(self.file_path, {})

            if self.ttl is not None:
                now = int(time.time())
                data = {
                    key: value
                    for key, value in data.items()
                    if now - value[1] < self.ttl
                }
            return data
        except Exception as exc:
            if self.debug:
                handle_exception(exc, False, False)

        return {}


    def dump(self, data: dict) -> None:
        """
        Stores the given data in the cache file.

        :param data: The data to be stored in the cache file.
        """

        PICKLE.dump(data, self.file_path)
