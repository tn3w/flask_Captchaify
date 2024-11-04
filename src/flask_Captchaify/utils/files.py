"""
files.py

This is a module for handling files and paths.

License:  GNU General Public License v3.0
    https://github.com/tn3w/flask_Captchaify/blob/master/LICENSE
Source:   https://github.com/tn3w/flask_Captchaify
"""

import os
import io
import json
import pickle
import shutil
import secrets
from threading import Lock
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from typing import Final, Optional, Tuple, Generator, Dict, Any

try:
    from utils.logger import log
except ImportError:
    try:
        from src.flask_Captchaify.utils.logger import log
    except ImportError:
        from logger import log


file_locks: Dict[str, Lock] = {}
WRITE_EXECUTOR: Final[ThreadPoolExecutor] = ThreadPoolExecutor()

CURRENT_DIRECTORY_PATH: Final[str] = os.path.dirname(os.path.abspath(__file__))
ROOT_DIRECTORY_PATH: Final[str] = CURRENT_DIRECTORY_PATH.replace("\\", "/").replace("//", "/")\
    .replace("//", "/").replace("utils", "").replace("//", "/")

# Create the file .env in the `src/flask_Captchaify` folder if you do
# not want to install the module with pip but want to import it from this
# folder, e.g. to display code changes directly.
TEST_FILE_PATH: Final[str] = os.path.join(ROOT_DIRECTORY_PATH, '.env')

def get_work_dir() -> str:
    """
    Determine the working directory for the application.

    Returns:
        str: The working directory path.
    """

    if os.path.exists(TEST_FILE_PATH):
        return ROOT_DIRECTORY_PATH

    try:
        import pkg_resources
    except ImportError:
        log("pkg_resources could not be imported, using root directory instead.", level = 3)
        return ROOT_DIRECTORY_PATH

    try:
        directory_path = pkg_resources.resource_filename('flask_Captchaify', '')
    except (pkg_resources.DistributionNotFound, pkg_resources.UnknownExtra, ModuleNotFoundError):
        log("`flask_Captchaify` package not found, using root directory instead.", level = 3)
        return ROOT_DIRECTORY_PATH

    if not os.path.exists(directory_path):
        log("package directory does not exist, using root directory instead.", level = 3)
        return ROOT_DIRECTORY_PATH

    return directory_path


WORK_DIRECTORY_PATH: Final[str] = get_work_dir()
DATA_DIRECTORY_PATH: Final[str] = os.path.join(WORK_DIRECTORY_PATH, "data")
ASSETS_DIRECTORY_PATH: Final[str] = os.path.join(WORK_DIRECTORY_PATH, "assets")
DATASETS_DIRECTORY_PATH: Final[str] = os.path.join(WORK_DIRECTORY_PATH, "datasets")
TEMPLATES_DIRECTORY_PATH: Final[str] = os.path.join(WORK_DIRECTORY_PATH, "templates")
TEMPLATE_ASSETS_DIRECTORY_PATH: Final[str] = os.path.join(TEMPLATES_DIRECTORY_PATH, "assets")

CAPTCHA_SECRET_FILE_PATH = os.path.join(
    DATA_DIRECTORY_PATH, 'secret.txt'
)
TRUECLICK_CAPTCHAS_FILE_PATH: Final[str] = os.path.join(
    DATA_DIRECTORY_PATH, "trueclick.pkl"
)
TRANSLATIONS_CACHE_FILE_PATH: Final[str] = os.path.join(
    DATA_DIRECTORY_PATH, "translation-cache.pkl"
)


@contextmanager
def dummy_context_manager(*args, **kwargs):
    """
    A dummy context manager that yields control and returns the provided arguments.

    Args:
        *args: Positional arguments to be captured and returned after the 
            context block is executed.
        **kwargs: Keyword arguments to be captured and returned after the 
            context block is executed.

    Yields:
        None: Control is yielded to the block of code using the context manager.

    Returns:
        Tuple: A tuple containing the positional and keyword arguments passed 
            to the context manager after the context block is executed.
    """

    yield
    return args, kwargs


def get_lock(file_path: str) -> Lock:
    """
    Retrieve or create a lock for the specified file.

    Args:
        file_path (str): The path to the file for which a lock is to be 
            retrieved or created.

    Returns:
        Lock: A threading.Lock object associated with the specified file path.
    """

    if not file_path in file_locks:
        new_lock = Lock()
        file_locks[file_path] = new_lock

        return new_lock

    return file_locks[file_path]


def delete_lock(file_path: str) -> None:
    """
    Remove the lock associated with the specified file.

    Args:
        file_path (str): The path to the file for which the lock should be 
            deleted.
    
    Returns:
        None: This function does not return a value.
    """

    if file_path in file_locks:
        del file_locks[file_path]


def get_shadow_copy_temp_path(file_path: str) -> str:
    """
    Generate a temporary file path for a shadow copy of the specified file.

    Args:
        file_path (str): The path to the original file for which a shadow 
            copy path is to be generated.

    Returns:
        str: The path to the temporary shadow copy file.
    """

    directory, file = os.path.split(file_path)

    random_hex = secrets.token_hex(16)
    temp_file_name = random_hex + "_" + file

    return os.path.join(directory, temp_file_name)


@contextmanager
def get_read_stream(file_path: str, read_as_bytes: bool = False,
                    shadow_copy: bool = True) -> Optional[Generator[io.TextIOWrapper, None, None]]:
    """
    Context manager for reading a file stream, with options for reading as 
    bytes and creating a shadow copy.

    Args:
        file_path (str): The path to the file to be read.
        read_as_bytes (bool, optional): If True, the file will be opened in 
            binary mode. Defaults to False (text mode).
        shadow_copy (bool, optional): If True, a temporary shadow copy of the 
            file will be created for reading. Defaults to True.

    Yields:
        Optional[Generator[io.TextIOWrapper, None, None]]: A file stream object 
            that can be used to read the contents of the file. The type of the 
            stream will depend on the `read_as_bytes` parameter.
    """

    mode = "r" + ("b" if read_as_bytes else "")
    encoding = None if read_as_bytes else "utf-8"

    if not os.path.isfile(file_path):
        yield None
        return

    temp_file_path = get_shadow_copy_temp_path(file_path) if shadow_copy else file_path

    try:
        if shadow_copy:
            shutil.copy2(file_path, temp_file_path)

        with open(temp_file_path, mode, encoding = encoding) as file_stream:
            yield file_stream

    finally:
        if shadow_copy:
            os.unlink(temp_file_path)


def read(file_path: str, default: Optional[Any] = None,
         read_as_bytes: bool = False, shadow_copy: bool = True) -> Optional[Tuple[str, bytes, Any]]:
    """
    Read the contents of a file and return its data.

    Args:
        file_path (str): The path to the file to be read.
        default (Optional[Any]): The value to return if the file cannot 
            be read or an error occurs. Defaults to None.
        read_as_bytes (bool): If True, the file will be read in binary mode. 
            If False, it will be read as text. Defaults to False.

    Returns:
        Optional[Tuple[str, bytes, Any]]: The contents of the file as a string 
                                          or bytes, or the default value if 
                                          the file cannot be read.
    """

    try:
        with get_read_stream(file_path, read_as_bytes, shadow_copy) as file_stream:
            if file_stream is not None and file_stream.readable():
                return file_stream.read()

    except (FileNotFoundError, IsADirectoryError, OSError, IOError,
            PermissionError, ValueError, TypeError, UnicodeDecodeError):
        log(f"`{file_path}` could not be read.", level = 4)

    return default


@contextmanager
def get_write_stream(file_path: str, write_as_bytes: bool = False, make_sure: bool = True,
                     shadow_copy: bool = True) -> Optional[Generator[io.TextIOWrapper, None, None]]:
    """
    Context manager for writing to a file stream, with options for creating 
    a shadow copy and ensuring data integrity.

    Args:
        file_path (str): The path to the file where the content will be written.
        write_as_bytes (Tuple[str, bytes]): Determines the mode in which the file
            is opened (text or binary).
        make_sure (bool, optional): If True, the file will be flushed and 
            synchronized to disk after writing. Defaults to True.
        shadow_copy (bool, optional): If True, a temporary shadow copy of the 
            file will be created for writing. Defaults to True.

    Yields:
        Optional[Generator[io.TextIOWrapper, None, None]]: A file stream object 
        that can be used to write the specified content to the file.
    """


    mode = "w" + ("b" if write_as_bytes else "")
    encoding = None if write_as_bytes else "utf-8"
    write_file_path = get_shadow_copy_temp_path(file_path) if shadow_copy else file_path
    lock_context_manager = dummy_context_manager if shadow_copy else get_lock

    try:
        with lock_context_manager(write_file_path):
            with open(write_file_path, mode, encoding = encoding) as file_stream:
                yield file_stream

                if make_sure:
                    file_stream.flush()
                    os.fsync(file_stream.fileno())

    finally:
        if shadow_copy and write_file_path != file_path:
            shutil.move(write_file_path, file_path)


def execute_write(content: Tuple[str, bytes], file_path: str, make_sure: bool = False,
                  shadow_copy: bool = True) -> bool:
    """
    Write content to a specified file.

    Args:
        content (Tuple[str, bytes]): The content to be written to the file. 
                                     This can be a string or bytes.
        file_path (str): The path to the file where the content will be written.
        make_sure (bool): If True, flushes the file buffer to disk after writing.
        shadow_copy (bool): If True, uses a temporary shadow copy.

    Returns:
        bool: True if the content was successfully written to the file, 
              False otherwise.
    """

    try:
        with get_write_stream(file_path, isinstance(content, bytes),
                              make_sure, shadow_copy) as file_stream:
            if file_stream is not None and file_stream.writable():
                file_stream.write(content)
                return True

    except (FileNotFoundError, IsADirectoryError, OSError, IOError,
            PermissionError, ValueError, TypeError, UnicodeDecodeError):
        log(f"`{file_path}` could not be writen.", level = 4)

    return False


def write(content: Tuple[str, bytes], file_path: str, make_sure: bool = False,
          shadow_copy: bool = False, as_thread: bool = False) -> bool:
    """
    Write content to a specified file, with options for execution mode.

    Args:
        content (Tuple[str, bytes]): The content to be written to the file. 
                                     This can be a string or bytes.
        file_path (str): The path to the file where the content will be written.
        make_sure (bool): If True, ensures that the content is flushed to disk 
                          after writing.
        shadow_copy (bool): If True, uses a temporary shadow copy.
        as_thread (bool): If True, executes the write operation in a separate thread.

    Returns:
        bool: True if the write operation was initiated successfully, 
              False if executed synchronously and the content was not written.
    """

    if as_thread:
        WRITE_EXECUTOR.submit(execute_write, content, file_path, make_sure, shadow_copy)
        return True

    return execute_write(content, file_path, make_sure, shadow_copy)


def is_directory_empty(directory_path: str) -> bool:
    """
    Check if a specified directory is empty.

    Args:
        directory_path (str): The path to the directory to be checked.

    Returns:
        bool: True if the directory does not exist or is empty, 
              False if it contains any files or subdirectories.
    """

    if not os.path.isdir(directory_path):
        return True

    return len(os.listdir(directory_path)) == 0


def delete(object_path: str) -> bool:
    """
    Delete a specified file or directory and its contents.

    Args:
        object_path (str): The path to the object (file or directory) to be deleted.

    Returns:
        bool: True if the object was successfully deleted, 
              False if the object type is unknown or an error occurred during deletion.
    """

    if not os.path.exists(object_path):
        return False

    if os.path.isfile(object_path):
        try:
            os.remove(object_path)
            return True

        except (PermissionError, IsADirectoryError, OSError,
                FileNotFoundError, ValueError):
            log(f"`{object_path}` could not be deleted.", level = 4)

        return False

    shutil.rmtree(object_path)
    return True


class CachedFile:
    """
    A interface for an file type with caching.
    """


    @property
    def _as_bytes(self) -> bool:
        return True


    def __init__(self) -> None:
        self._data = {}


    def _get_cache(self, file_path: str) -> Any:
        """
        Gets the cached value for the given file path.

        Args:
            file_path (str): The path to the file to get the cached value for.

        Returns:
            Any: The cached value for the given file path.
        """

        return self._data.get(file_path)


    def _set_cache(self, file_path: str, value: Any) -> None:
        """
        Sets the cached value for the given file path.

        Args:
            file_path (str): The path to the file to set the cached value for.
            value (Any): The value to set the cached value to.
        
        Returns:
            None
        """

        self._data[file_path] = value


    def _load(self, file_stream: io.TextIOWrapper) -> Any:
        try:
            if file_stream.readable():
                return file_stream.read()

        except (FileNotFoundError, IsADirectoryError, OSError, IOError,
                PermissionError, ValueError, TypeError, UnicodeDecodeError):
            log(f"`{file_stream.name}` could not be loaded. (CachedFile)", level = 4)

        return None


    def _dump(self, data: Any, file_stream: io.TextIOWrapper) -> bool:
        try:
            if file_stream.writable():
                file_stream.write(data)
                return True

        except (FileNotFoundError, IsADirectoryError, OSError, IOError,
                PermissionError, ValueError, TypeError, UnicodeDecodeError):
            log(f"`{file_stream.name}` could not be dumped. (CachedFile)", level = 4)

        return False


    def load(self, file_path: str, default: Any = None) -> Any:
        """
        Loads the file.

        Args:
            file_path (str): The path to the file to load.
            default (Any, optional): The default value to return if the file
                                     does not exist. Defaults to None.

        Returns:
            Any: The loaded file.
        """

        file_data = self._get_cache(file_path)

        if file_data is not None:
            return file_data

        with get_read_stream(file_path, self._as_bytes) as file_stream:
            if file_stream:
                data = self._load(file_stream)
                if data is not None:
                    self._set_cache(file_path, data)

                    return data

        return default


    def dump(self, data: Any, file_path: str) -> bool:
        """
        Dumps the data to the file.

        Args:
            data (Any): The data to dump to the file.
            file_path (str): The path to the file to dump the data to.
        
        Returns:
            bool: True if the data was dumped successfully, False otherwise.
        """

        try:
            with get_write_stream(file_path, self._as_bytes, True, True) as file_stream:
                if file_stream is None:
                    return False

                WRITE_EXECUTOR.submit(self._dump, data, file_stream)
                return True

        except (pickle.PicklingError, ValueError):
            pass

        return False


class PICKLEFile(CachedFile):
    """
    A pickle file type with caching.
    """


    def _load(self, file_stream: io.TextIOWrapper) -> Any:
        try:
            if os.stat(file_stream.name).st_size == 0:
                log(f"`{file_stream.name}` is empty. (PICKLEFile)", level=4)
                return None

            return pickle.load(file_stream)
        except pickle.UnpicklingError:
            log(f"`{file_stream.name}` could not be loaded. (PICKLEFile)", level = 4)

        return None


    def _dump(self, data: Any, file_stream: io.TextIOWrapper) -> bool:
        try:
            pickle.dump(data, file_stream)

            return True
        except pickle.PicklingError:
            log(f"`{file_stream.name}` could not be dumped. (PICKLEFile)", level = 4)

        return False


class JSONFile(CachedFile):
    """
    A JSON file type with caching.
    """

    @property
    def _as_bytes(self) -> bool:
        return False


    def _load(self, file_stream: io.TextIOWrapper) -> Any:
        try:
            return json.load(file_stream)
        except json.JSONDecodeError:
            log(f"`{file_stream.name}` could not be loaded. (JSONFile)", level = 4)

        return None


    def _dump(self, data: Any, file_stream: io.TextIOWrapper) -> bool:
        try:
            json.dump(data, file_stream)

            return True
        except ValueError:
            log(f"`{file_stream.name}` could not be dumped. (JSONFile)", level = 4)

        return False


PICKLE = PICKLEFile()
JSON = JSONFile()
