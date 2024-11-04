import os
import time
import pickle
from typing import Final, Optional, Union, Tuple, Dict, List, Any

try:
    from utils.crypto.hashing import SHA256
    from utils.crypto.symmetric import AES256
    from utils.logger import log
    from utils.files import PICKLE, DATA_DIRECTORY_PATH
except ImportError:
    try:
        from src.flask_Captchaify.utils.crypto.hashing import SHA256
        from src.flask_Captchaify.utils.crypto.symmetric import AES256
        from src.flask_Captchaify.utils.logger import log
        from src.flask_Captchaify.utils.files import PICKLE, DATA_DIRECTORY_PATH
    except ImportError:
        from crypto.hashing import SHA256
        from crypto.symmetric import AES256
        from logger import log
        from files import PICKLE, DATA_DIRECTORY_PATH


SHA: Final[SHA256] = SHA256(1000, salt_length = 8)
CUSTOM_EPOCH_OFFSET = int(time.mktime((2010, 1, 1, 0, 0, 0, 0, 0, 0)))
CUSTOM_EPOCH_OFFSET_NS = CUSTOM_EPOCH_OFFSET * 1_000_000_000


def get_time() -> int:
    """
    Returns the current timestamp in seconds relative to the 2010 epoch.

    Returns:
        int: The current time in seconds from the 2010 epoch.
    """

    return int(time.time()) - CUSTOM_EPOCH_OFFSET


def get_time_ns() -> int:
    """
    Returns the current timestamp in nanoseconds relative to the 2010 epoch.

    Returns:
        int: The current time in nanoseconds from the 2010 epoch.
    """

    return time.time_ns() - CUSTOM_EPOCH_OFFSET_NS


class SSES:
    """
    Space-saving encryption scheme (SSES) for encrypting data without keys and decrypting with keys.
    """


    def __init__(self, password: str, separator: str = '\x00',
                 with_keys: bool = False, debug: bool = False) -> None:
        """
        Initializes the SSES instance with the specified encryption parameters.

        Args:
            password (str): A secure encryption password, should be at least 32 characters long.
            separator (str): The separator string to use for joining values before encryption.
                Defaults to '\x00' (null byte).
            with_keys (bool): Whether to include keys during encryption. Defaults to False.
            debug (bool): Whether to throw error messages directly. Defaults to False.
        """

        self.password = password
        self.separator = separator
        self.with_keys = with_keys
        self.debug = debug

        super().__init__()


    @property
    def aes(self) -> AES256:
        return AES256(self.password, serialization = "base62")


    def _serialize_value(self, value) -> str:
        """
        Serializes a single value with length-prefix encoding.

        Args:
            value (Any): The value to be serialized.

        Returns:
            str: The serialized value with a length prefix.
        """

        serialized = pickle.dumps(value)
        length_prefix = f"{len(serialized)}".encode()
        return length_prefix + self.separator.encode() + serialized


    def _deserialize_value(self, data: bytes) -> object:
        """
        Deserializes a single value from length-prefix encoding.

        Args:
            data (bytes): The data to be deserialized, including length prefix.

        Returns:
            object: The deserialized object.
        """

        length_str, _, serialized_value = data.partition(self.separator.encode())
        length = int(length_str)
        return pickle.loads(serialized_value[:length])


    def encrypt(self, data_dict: Dict[str, object]) -> Optional[str]:
        """
        Encrypts the provided dictionary of values.

        Args:
            data_dict (dict): A dictionary containing key-value pairs to encrypt.

        Returns:
            Optional[str]: The encrypted data as a string, or None if encryption fails.
        """

        try:
            if not self.with_keys:
                serialized_data = [
                    self._serialize_value(value)
                    for value in data_dict.values()
                ]
                text_data = self.separator.encode().join(serialized_data)
            else:
                text_data = pickle.dumps(data_dict)

            encrypted_data = self.aes.encrypt(text_data.decode())
            return encrypted_data

        except Exception as exception:
            log(f"Error while encrypting with SSES: {exception}", level = 4)

        return None


    def decrypt(self, encrypted_data: str, dict_keys: Optional[List[str]] = None) \
            -> Optional[Union[Dict[str, object], List[object]]]:
        """
        Decrypts the provided encrypted data.

        Args:
            encrypted_data (str): The encrypted data to decrypt.
            dict_keys (Optional[List[str]]): A list of keys to use for forming a dictionary
                from decrypted values. If not provided, the result will be a list.

        Returns:
            Optional[Union[Dict[str, object], List[object]]]: The decrypted data as either a
                dictionary (if dict_keys is provided) or a list, or None if decryption fails.
        """

        try:
            decrypted_data = self.aes.decrypt(encrypted_data)

            if self.with_keys:
                return pickle.loads(decrypted_data.encode())

            data_parts = decrypted_data.encode().split(self.separator.encode())
            values = [self._deserialize_value(part) for part in data_parts if part]

            if not isinstance(dict_keys, list) or len(dict_keys) == 0:
                return values

            data_dict = {
                dict_keys[i]: values[i]
                for i in range(min(len(dict_keys), len(values)))
            }

            return data_dict

        except Exception as exception:
            log(f"Error while decrypting with SSES: {exception}", level = 4)

        return None


class DatabaseInterface(dict):
    """
    An interface for database types.
    """

    def __init__(self, file_name: str, dir_path: Optional[str] = None,\
                 store_anonymously: bool = False, ttl: Optional[int] = 259200,
                 max_size: int = 12) -> None:
        """
        Initializes the DatabaseInterface object with specified settings.

        Args:
            file_name (str): The name of the file to store time data.
            dir_path (Optional[str]): The directory path to store time data.
            store_anonymously (bool): If True, stores time data without directly 
                associating it with the key.
            ttl (int): The time-to-live in seconds, after which time data
                will be removed. Defaults to 259200 (3 days).
            max_size (int): The maximum number of timestamps to store per key. Defaults to 12.
        """

        if not file_name.endswith('.db'):
            file_name += '.db'

        if dir_path is None:
            dir_path = DATA_DIRECTORY_PATH

        self.file_path = os.path.join(dir_path, file_name)
        self.store_anonymously = store_anonymously
        self.ttl = ttl
        self.max_size = max_size


    def _load(self) -> dict:
        return PICKLE.load(self.file_path, {})


    def _load_and_clean(self) -> dict:
        data = self._load()

        if not data:
            return data

        return self._clean(data)


    def _dump(self, data: dict) -> bool:
        return PICKLE.dump(data, self.file_path)


    def _clean(self, data: dict) -> bool:
        current_time = get_time()

        return {
            key: (value, timestamp)
            for key, (value, timestamp) in data.items()
            if current_time - timestamp <= self.ttl
        }


class TimeStorage(DatabaseInterface):
    """
    A class to store time data in a file.
    """

    def _clean(self, data: dict) -> dict:
        """
        Removes expired timestamps from the data dictionary.

        Args:
            data (dict): The data dictionary to clean.

        Returns:
            dict: The cleaned data with expired timestamps removed.
        """

        if not isinstance(data, dict):
            return {}

        current_time = get_time()

        new_data = {}
        for key, timestamps in data.items():
            new_timestamps = [
                ts for ts in timestamps
                if current_time - ts < self.ttl
            ]

            if new_timestamps:
                new_data[key] = new_timestamps[:self.max_size]

        return new_data


    def add_time(self, key: Any) -> None:
        """
        Adds the current timestamp to the specified key in the storage.

        Args:
            key (Any): The key to add the timestamp for.
        """

        data = self._load_and_clean()

        store_key = key
        if self.store_anonymously:
            for stored_key in data:
                if SHA.compare(key, stored_key):
                    store_key = stored_key
                    break
            else:
                store_key = SHA.hash(key)

        current_time = get_time()

        if store_key in data:
            data[store_key].insert(0, current_time)
            data[store_key] = data[store_key][:self.max_size]
        else:
            data[store_key] = [current_time]

        self._dump(data)


    def get_counts(self, key: Any) -> Tuple[int, int]:
        """
        Retrieves the count of timestamps for the specified
        key and the total count of all timestamps.

        Args:
            key (Any): The key to retrieve the count for.

        Returns:
            Tuple[int, int]: The count for the specified key and the total count across all keys.
        """

        data = self._load_and_clean()

        total_count = sum(len(timestamps) for timestamps in data.values())

        key_count = next(
            (
                len(timestamps)
                for stored_key, timestamps in data.items()
                if (
                    key == stored_key if not self.store_anonymously
                    else SHA.compare(key, stored_key)
                )
            ), 0
        )

        return key_count, total_count


class Cache(DatabaseInterface):
    """
    A dictionary-based cache with time-to-live (TTL) and optional anonymous storage.
    Data is stored and retrieved with encryption when in anonymous mode.
    """


    def _get_stored_key(self, key: str, data: dict) -> Optional[str]:
        """
        Retrieves the actual stored key for a given input key, considering anonymous storage.

        Args:
            key (str): The input key to look for.
            data (dict): The cache data dictionary to search within.

        Returns:
            Optional[str]: The stored key if found, otherwise None.
        """

        if not self.store_anonymously:
            return key

        for stored_key in data:
            if SHA.compare(key, stored_key):
                return stored_key

        return None


    def _get(self, key: str) -> Optional[Any]:
        """
        Retrieves the value and timestamp for a given key after loading and cleaning data.

        Args:
            key (str): The key to retrieve.

        Returns:
            Optional[Any]: The stored value if the key exists, otherwise None.
        """

        data = self._load_and_clean()
        stored_key = self._get_stored_key(key, data)

        return data.get(stored_key, None)


    def __getitem__(self, key: str) -> Optional[Any]:
        """
        Allows dictionary-style access to retrieve a value.

        Args:
            key (str): The key to retrieve.

        Returns:
            Optional[Any]: The value associated with the key, or None if not found.
        """

        return self.get(key)


    def __setitem__(self, key: str, value: Any) -> bool:
        """
        Allows dictionary-style access to set a value.

        Args:
            key (str): The key for the value to store.
            value (Any): The value to store.

        Returns:
            bool: True if the operation succeeded, otherwise False.
        """

        return self.set(key, value)


    def __delitem__(self, key: Any) -> bool:
        """
        Allows dictionary-style deletion of a key-value pair.

        Args:
            key (Any): The key to delete.

        Returns:
            bool: True if the key was successfully deleted, False if it was not found.
        """

        data = self._load_and_clean()
        stored_key = self._get_stored_key(key, data)

        try:
            del data[stored_key]
        except (KeyError, TypeError, NameError):
            return False

        return self._dump(data)


    def get(self, key: str) -> Optional[Any]:
        """
        Retrieves and decrypts (if necessary) the value associated with a given key.

        Args:
            key (str): The key to retrieve.

        Returns:
            Optional[Any]: The value if the key exists and is valid, otherwise None.
        """

        data = self._get(key)
        if not isinstance(data, tuple):
            return None

        value = data[0]

        if not self.store_anonymously:
            return value

        decrypted_value = AES256(key).decrypt(value)
        loaded_value = pickle.loads(decrypted_value)

        return loaded_value


    def set(self, key: str, value: Any) -> bool:
        """
        Stores a value associated with a key, encrypting it if anonymous storage is enabled.

        Args:
            key (str): The key for the value to store.
            value (Any): The value to store.

        Returns:
            bool: True if the operation succeeded, otherwise False.
        """

        if self.store_anonymously:
            hashed_key = SHA.hash(key)

            dumped_value = pickle.dumps(value)
            encrypted_value = AES256(key).encrypt(dumped_value)

            final_key = hashed_key
            final_value = encrypted_value
        else:
            final_key = key
            final_value = value

        data = self._load_and_clean()

        data[final_key] = (final_value, get_time())
        return self._dump(data)


    def exists(self, key: str) -> bool:
        """
        Checks if a key exists in the cache.

        Args:
            key (str): The key to check.

        Returns:
            bool: True if the key exists, otherwise False.
        """

        return self._get(key) is not None
