from secrets import choice
from gzip import decompress
from base64 import b64encode

import cv2
import numpy as np


def get_random_image(all_images: list[str]) -> bytes:
    """
    Retrieve a random image path from the list, decode it from base64, and return it.

    :param all_images: A list of image paths encoded as base64 strings.
    :return: The decoded image data as bytes.
    """

    random_image = choice(all_images)
    decompressed_data = decompress(random_image)

    return decompressed_data


def convert_image_to_base64(image_data: bytes) -> str:
    """
    Converts an image into Base64 Web Format

    :param image_data: The data of an image file in webp format
    :return: A data URL representing the image in Base64 Web Format
    """

    encoded_image = b64encode(image_data).decode('utf-8')

    data_url = f'data:image/png;base64,{encoded_image}'

    return data_url


def manipulate_image_bytes(image_data: bytes, is_small: bool = False,
                           hardness: int = 1) -> bytes:
    """
    Manipulates an image represented by bytes to create a distorted version.

    :param image_data: The bytes representing the original image.
    :param is_small: Whether the image should be resized to 100x100 or not.
    :param hardness: A number between 1 and 5 that determines the distortion factor.
    :return: The bytes of the distorted image.
    """

    img = cv2.imdecode(np.frombuffer(image_data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Image data could not be decoded.")

    height, width = img.shape[:2]

    if hardness > 3:
        num_dots = np.random.randint(20, 100) * (hardness - 3)
        dot_coords = np.random.randint(0, [width, height], size=(num_dots, 2))
        colors = np.random.randint(0, 256, size=(num_dots, 3))

        for (x, y), color in zip(dot_coords, colors):
            img[y, x] = color

        num_lines = np.random.randint(20, 100) * (hardness - 3)
        start_coords = np.random.randint(0, [width, height], size=(num_lines, 2))
        end_coords = np.random.randint(0, [width, height], size=(num_lines, 2))
        colors = np.random.randint(0, 256, size=(num_lines, 3))

        for (start, end), color in zip(zip(start_coords, end_coords), colors):
            cv2.line(img, tuple(start), tuple(end), color.tolist(), 1)

    max_shift = max(3, hardness + 1)
    x_shifts = np.random.randint(-max(2, hardness + 4), max_shift, size=(height, width))
    y_shifts = np.random.randint(-max(1, hardness + 4), max_shift, size=(height, width))

    map_x, map_y = np.meshgrid(np.arange(width), np.arange(height))
    map_x = (map_x + x_shifts) % width
    map_y = (map_y + y_shifts) % height

    shifted_img = cv2.remap(
        img, map_x.astype(np.float32),
        map_y.astype(np.float32), cv2.INTER_LINEAR
    )
    shifted_img_hsv = cv2.cvtColor(shifted_img, cv2.COLOR_BGR2HSV)

    shifted_img_hsv[..., 1] = np.clip(shifted_img_hsv[..., 1] * (1 + hardness * 0.12), 0, 255)
    shifted_img_hsv[..., 2] = np.clip(shifted_img_hsv[..., 2] * (1 - hardness * 0.09), 0, 255)

    shifted_img = cv2.cvtColor(shifted_img_hsv, cv2.COLOR_HSV2BGR)
    shifted_img = cv2.GaussianBlur(shifted_img, (5, 5), hardness * 0.1)

    size = 100 if is_small else 200
    shifted_img = cv2.resize(shifted_img, (size, size), interpolation=cv2.INTER_LINEAR)

    _, output_bytes = cv2.imencode('.png', shifted_img)
    if not _:
        raise ValueError("Image encoding failed.")

    return output_bytes.tobytes()
