import os
import json
import gzip
import random
import urllib.request
from io import BytesIO
from threading import Lock
from base64 import b64encode, b64decode
from typing import Union, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed


file_locks = {}


def resize_image(image_data: bytes, target_size: int | int =\
                 (200, 200), crop: bool = False) -> bytes | None:
    """
    Resizes the given image data to the specified target size and saves it as a WEBP image.

    :param image_data: Bytes representing the image.
    :param target_size: Tuple representing the target size (width, height).
    """

    from PIL import Image

    try:
        image = Image.open(BytesIO(image_data))

        if crop:
            width, height = image.size
            crop_amount = min(width, height) // 8
            left = crop_amount
            top = crop_amount
            right = width - crop_amount
            bottom = height - crop_amount

            cropped_image = image.crop((left, top, right, bottom))
        else:
            cropped_image = image

        resized_image = cropped_image.resize(target_size, Image.LANCZOS)

        bytes_io = BytesIO()
        resized_image.save(bytes_io, format='WEBP', quality=80)
        webp_data = bytes_io.getvalue()

        compressed_data = gzip.compress(webp_data, 9)

        str_data = b64encode(compressed_data).decode('utf-8')

        return str_data
    except Exception:
        pass

    return None


def download_file(url: str) -> str:
    """
    Downloads an image from the given URL and resizes it.

    :param url: The URL of the image to download.
    :return: The resized image as a base64 encoded string.
    """

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            image_data = response.read()

            resized_image = resize_image(image_data)
            return resized_image

    except Exception:
        pass

    return None


def set_key(file_path: str, key: any, value: any) -> None:
    """
    Sets a key-value pair in a JSON file.

    :param file_path: The path to the JSON file.
    :param key: The key to set.
    :param value: The value to set for the key.
    """

    data = JSON.load(file_path, default={})
    data[key] = value

    with open(file_path, 'w', encoding='utf-8') as writeable_file:
        json.dump(data, writeable_file)


def download_images(file_path: str, key: str, image_urls: list[str]) -> None:
    """
    Downloads images from a list of URLs and saves them
    in the specified file_path under the specified key.

    :param file_path: The path to the file where the images will be saved.
    :param key: The key under which the images will be saved in the file.
    :param image_urls: A list of URLs from which the images will be downloaded.
    """

    key_downloaded_images = []

    with ThreadPoolExecutor() as executor:
        futures = []
        for url in image_urls:
            f = executor.submit(download_file, url)
            futures.append(f)

        for future in as_completed(futures):
            resized_image = future.result()

            if resized_image is not None:
                key_downloaded_images.append(resized_image)

    if len(key_downloaded_images) < 2:
        return

    set_key(file_path, key, key_downloaded_images)


def get_random_image(all_images: list[str]) -> str:
    """
    Retrieve a random image path from the list, decode it from base64, and return it.

    :param all_images: A list of image paths encoded as base64 strings.
    :return: The decoded image data as a string.
    """

    random_image = random.choice(all_images)
    decoded_image = b64decode(random_image.encode('utf-8'))
    decompressed_data = gzip.decompress(decoded_image)

    return decompressed_data


def convert_image_to_base64(image_data: bytes) -> str:
    """
    Converts an image into Base64 Web Format

    :param image_data: The data of an image file in webp format
    :return: A data URL representing the image in Base64 Web Format
    """

    encoded_image = b64encode(image_data).decode('utf-8')

    data_url = f'data:image/webp;base64,{encoded_image}'

    return data_url


def find_missing_numbers_in_range(range_start: int, range_end: int, data: list):
    """
    Finds missing numbers within a given range excluding the ones provided in the data.

    :param range_start: The start value of the range.
    :param range_end: The end value of the range.
    :param data: A list containing tuples of numbers and their associated data.
    """

    numbers = list(range(range_start + 1, range_end + 1))

    for item in data:
        if item[0] in numbers:
            numbers.remove(item[0])

    return numbers


class Json:
    """
    Class for loading / saving JavaScript Object Notation (= JSON)
    """

    def __init__(self) -> None:
        self.data = {}


    def load(self, file_path: str, default: Optional[
             Union[dict, list]] = None) -> Union[dict, list]:
        """
        Function to load a JSON file securely.

        :param file_path: The JSON file you want to load
        :param default: Returned if no data was found
        """

        if default is None:
            default = {}

        if not os.path.isfile(file_path):
            return default

        if file_path not in file_locks:
            file_locks[file_path] = Lock()

        with file_locks[file_path]:
            try:
                with open(file_path, 'r', encoding = 'utf-8') as file:
                    data = json.load(file)
            except Exception:
                if self.data.get(file_path) is not None:
                    self.dump(self.data[file_path], file_path)
                    return self.data
                return default
        return data


    def dump(self, data: Union[dict, list], file_path: str) -> bool:
        """
        Function to save a JSON file securely.
        
        :param data: The data to be stored should be either dict or list
        :param file_path: The file to save to
        """

        file_directory = os.path.dirname(file_path)
        if not os.path.isdir(file_directory):
            return False

        if file_path not in file_locks:
            file_locks[file_path] = Lock()

        with file_locks[file_path]:
            self.data = data
            try:
                with open(file_path, 'w', encoding = 'utf-8') as file:
                    json.dump(data, file)
            except Exception as exc:
                print(exc)
        return True


JSON = Json()


class Block:
    """
    Functions for saving data in blocks instead of alone
    """


    def __init__(self, block_size: int = 1, file_path: Optional[str] = None) -> None:
        """
        Initializes a Block object.

        :param block_size: How big each block is.
        :param file_path: The name of the file to write the block to.
        """

        if not isinstance(file_path, str):
            raise ValueError("File path must be a string.")

        self.block_size = block_size
        self.file_path = file_path

        self.blocks = {}


    def _get_id(self, index: int) -> int:
        """
        Returns the nearest block index based on the given index and block size.

        :param index: The index value.
        """

        remains = index % self.block_size

        if remains == 0:
            return index
        return index + (self.block_size - remains)


    def _write_data(self, block_data: tuple) -> None:
        """
        Writes data to a file while ensuring thread safety using locks.

        :param block_data: A tuple containing data to be written to the file.
        """

        data = JSON.load(self.file_path, default=[])

        for _, new_data in block_data:
            if new_data is not None:
                data.append(new_data)

        JSON.dump(data, self.file_path)


    def add_data(self, index: int, new_data: Optional[dict] = None) -> Tuple[bool, Optional[int]]:
        """
        Adds new data to the specified index in the data structure, and writes the block to file
        if all expected data within the block range is present.

        :param index: The index where the new data should be added.
        :param new_data: The data to be added, if any.
        """

        block_id = self._get_id(index)

        block = self.blocks.get(block_id, [])
        block.append((index, new_data))
        self.blocks[block_id] = block

        missing = find_missing_numbers_in_range(block_id - self.block_size, block_id, block)
        if 1 in missing:
            missing.remove(1)

        if len(missing) == 0:
            print('Writing block', block_id)
            self._write_data(block)

            del self.blocks[block_id]

            return True, block_id
        return False, block_id


    @property
    def size(self) -> int:
        """
        Returns the size of the data structure.

        Checks if the file exists and if so, loads the data from the file using the 'load' function.
        Returns the length of the loaded data. If the file does not exist, returns 0.

        :return: The size of the data structure.
        """

        data = JSON.load(self.file_path, default=[])
        return len(data)
