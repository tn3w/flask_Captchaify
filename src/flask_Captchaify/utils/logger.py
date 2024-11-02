"""
logging.py

This is a module for logging to the console or to a file.

License:  GNU General Public License v3.0
    https://github.com/tn3w/flask_Captchaify/blob/master/LICENSE
Source:   https://github.com/tn3w/flask_Captchaify
"""

import os
import shutil
import secrets
from sys import exc_info
from time import time_ns
from datetime import datetime
from traceback import format_exc
from typing import Optional, Final, Any
from concurrent.futures import ThreadPoolExecutor


CURRENT_DIRECTORY_PATH: Final[str] = os.path.dirname(os.path.abspath(__file__))\
    .replace("\\", "/").replace("//", "/") .replace("//", "/").replace("utils", "")\
        .replace("//", "/")

LOG_MAX_LINES: Final[int] = 30000
LOG_EXECUTOR: Final[ThreadPoolExecutor] = ThreadPoolExecutor()
LOG_LEVELS: Final[dict] = {
    1: "INFO",
    2: "NOTICE",
    3: "WARN",
    4: "ERROR"
}

QUIET: bool = False
LOG_DIRECTORY_PATH: str = CURRENT_DIRECTORY_PATH


def set_quiet(quiet: bool) -> None:
    """
    Set the global QUIET variable to control the verbosity of logging.

    Args:
        quiet (bool): If True, sets QUIET to True, silencing log output. 
                      If False, enables log output.
    """

    global QUIET
    QUIET = quiet


def set_log_directory_path(log_directory_path: str) -> None:
    """
    Set the global LOG_DIRECTORY_PATH variable to specify the directory 
    where log files will be stored.

    Args:
        log_directory_path (str): The path to the directory for log files.
    """

    global LOG_DIRECTORY_PATH
    LOG_DIRECTORY_PATH = log_directory_path


def _is_convertible_to_string(entity: Any) -> bool:
    """
    Determine if the given entity can be converted to a string.

    This function checks if the entity has a __str__ or __repr__ method 
    that is callable. If either method is present and callable, the 
    entity is considered convertible to a string.

    Args:
        entity (Any): The entity to check for string conversion capability.

    Returns:
        bool: True if the entity can be converted to a string, 
            False otherwise.
    """

    return hasattr(entity, "__str__") and callable(entity.__str__) or \
           hasattr(entity, "__repr__") and callable(entity.__repr__)


def _get_shadow_copy_temp_path(file_path: str) -> str:
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


def _read(file_path: str) -> Optional[str]:
    """
    Read the content of a file and return it as a string.

    Args:
        file_path (str): The path to the file to be read.

    Returns:
        Optional[str]: The content of the file as a string, or None 
            if the file does not exist or an error occurs.
    """

    exists = os.path.isfile(file_path)

    temp_file_path = _get_shadow_copy_temp_path(file_path) if exists else file_path
    if exists:
        shutil.copy2(file_path, temp_file_path)

    content = None
    try:
        with open(temp_file_path, "r", encoding = "utf-8") as file_stream:
            if file_stream is not None and file_stream.readable():
                content = file_stream.read()

    except (FileNotFoundError, IsADirectoryError, OSError, IOError,
            PermissionError, ValueError, TypeError, UnicodeDecodeError):
        pass

    if exists:
        os.unlink(temp_file_path)

    return content


def _write(message: str, file_path: str) -> bool:
    """
    Write a message to a specified file.

    Args:
        message (str): The message to be written to the file.
        file_path (str): The path to the file where the message will be written.

    Returns:
        bool: True if the message was successfully written, False otherwise.
    """

    temp_file_path = _get_shadow_copy_temp_path(file_path)
    try:
        with open(temp_file_path, "w", encoding = "utf-8") as file_stream:
            if file_stream is not None and file_stream.writable():
                file_stream.write(message)

    except (FileNotFoundError, IsADirectoryError, OSError, IOError,
            PermissionError, ValueError, TypeError, UnicodeDecodeError):
        return False

    shutil.move(temp_file_path, file_path)
    return True



def _append_to_log(new_log_item: str, log_file_path: str) -> bool:
    """
    Append a new log item to the specified log file.

    Args:
        new_log_item (str): The new log item to be added.
        log_file_path (str): The path to the log file.

    Returns:
        bool: True if the log item was successfully appended, False otherwise.
    """

    log_content = _read(log_file_path)
    if log_content is None:
        log_content = ""

    log_content = new_log_item + "\n" + log_content

    log_lines = log_content.split("\n")
    log_content = "\n".join(log_lines[: LOG_MAX_LINES]).strip()

    return _write(log_content, log_file_path)


def _execute_log(message: str, *args, level: int = 1, exception: Optional[str] = None,
                 quiet: bool = True, log_directory_path: str = None):
    """
    Format and execute logging of a message.

    Args:
        message (str): The main log message to be recorded.
        *args: Additional arguments to be included in the log message.
        level (int, optional): The log level (default is 1).
        exception (Optional[str], optional): An exception message to include, if any.
        quiet (bool, optional): If True, suppress console output (default is True).
        log_directory_path (str, optional): The directory path for the log file.
    """

    current_ns_time = time_ns()
    formatted_timestamp = datetime.fromtimestamp(current_ns_time / 1e9)\
        .strftime("%Y-%m-%d %H:%M:%S.%f") + str(current_ns_time)[-3:]

    full_message = "[flask_Captchaify " + LOG_LEVELS.get(level, "INFO") + " at "\
        + formatted_timestamp + "] " + str(message)

    for arg in args:
        if not isinstance(arg, str):
            if not _is_convertible_to_string(arg):
                continue

            arg = str(arg)

        full_message += " " + arg

    if exception is not None:
        full_message += "\n" + exception

    if not quiet:
        print(full_message)
        return

    log_file_path = os.path.join(log_directory_path, "log.txt")

    was_written = _append_to_log(full_message, log_file_path)
    if not was_written:
        print(full_message)


def log(message: str, *args, level: int = 1) -> None:
    """
    Log a message asynchronously with optional additional arguments.

    Args:
        message (str): The main log message to be recorded.
        *args: Additional arguments to be included in the log message.
        level (int, optional): The log level (default is 1). 
                               Higher values may indicate more severe log levels.
    """

    exception = None
    if exc_info()[0] is not None:
        exception = format_exc()

    LOG_EXECUTOR.submit(
        _execute_log, message, *args, level = level, exception = exception,
        quiet = QUIET, log_directory_path = LOG_DIRECTORY_PATH
    )
