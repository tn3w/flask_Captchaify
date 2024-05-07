"""
-~- flask_Captchaify Datasets -~-
https://github.com/tn3w/flask_Captchaify
Made with 💩 in Germany by TN3W

This code is designed to generate images to facilitate the
creation of captcha images and ensure their compatibility for
captcha implementation.

Under the open source license GPL-3.0 license, supported by Open Source Software
"""

import os
import random
import json
from io import BytesIO
import gzip
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Final
from duckduckgo_search import DDGS
import requests
from PIL import Image


DATASET_NAME: Final[str] = 'custom_dataset.json'
DATASET_SIZE: Final[tuple[int]] = (200, 140)
# the first number indicates how many images are downloaded per keyword
# the second number indicates how many keywords can be used


KEYWORDS: Final[list] = [
    'hiking trail', 'moonlit forest', 'volcano', 'skyscraper', 'moonlight',
    'island', 'duck', 'temple', 'wheat field', 'bluebonnet field', 'bamboo',
    'zebra', 'jellyfish', 'eclipse', 'wildflower meadow', 'crystal cave',
    'polar bear', 'desert oasis', 'surfing', 'forest', 'pagoda', 'ancient ruins',
    'glowing jellyfish', 'sloth', 'snowy owl', 'bioluminescent bay',
    'bonsai tree', 'hot air balloon', 'beach', 'gondola', 'parrot', 'orchid',
    'ocean', 'starfish', 'river', 'car', 'castle', 'desert', 'butterfly',
    'starry sky', 'fireworks', 'tiger', 'mountain', 'waterfall',
    'bamboo grove', 'sunflower', 'peacock', 'beaver', 'dolphin', 'sunny beach',
    'chapel', 'maple tree', 'canal', 'whale', 'fairy lights', 'windmill',
    'panda', 'giant tortoise', 'sushi', 'starry night', 'lily pads', 'statue',
    'avalanche', 'seahorse', 'toucan', 'dragonfly', 'barn', 'space shuttle',
    'sand dunes', 'ice cave', 'rainbow', 'robin', 'mountain peak', 'water lilies',
    'cherry blossom', 'koala', 'moon', 'puffin', 'wisteria', 'rice terraces',
    'swan', 'tropical fish', 'pyramid', 'cat', 'penguin', 'garden', 'glacier',
    'aurora', 'firefly', 'giraffe', 'thunderstorm', 'carnival', 'aurora borealis',
    'nebula', 'canyon', 'cottage', 'bamboo forest', 'cave', 'carousel', 'sakura tree',
    'cactus', 'mushroom', 'redwood forest', 'coral reef', 'cathedral', 'mountain lake',
    'lighthouse', 'lakeside', 'northern lights', 'city skyline', 'fox', 'jungle',
    'hibiscus', 'arctic wolf', 'squirrel', 'rose garden', 'vineyard', 'universe',
    'palm tree', 'lavender field', 'iceberg', 'ancient temple', 'sunset', 'kangaroo',
    'forest', 'lotus flower', 'snowflake', 'eagle', 'glacier bay', 'corn field',
    'tent', 'koi pond', 'monarch butterfly', 'moonlit beach', 'lizard', 'dog',
    'snake', 'bird', 'camel', 'lion', 'cow'
]

HEADER: Final[dict[str]] = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '+
                  '(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.3'
}


def resize_image(image_data: bytes, target_size: int | int =\
                  (200, 200), crop: bool = False) -> bytes | None:
    """
    Resizes the given image data to the specified target size and saves it as a WEBP image.

    :param image_data: Bytes representing the image.
    :param target_size: Tuple representing the target size (width, height).
    """

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
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def download_file(url: str) -> str:
    try:
        resp = requests.get(url, headers = HEADER, timeout=10)
        resp.raise_for_status()

        resized_image = resize_image(resp.content)
        return resized_image
    except Exception as e:
        print(e)


def set_keyword(keyword: str, data: list[str]) -> None:
    if os.path.isfile(DATASET_NAME):
        with open(DATASET_NAME, 'r', encoding = 'utf-8') as readable_file:
            dataset_images = json.load(readable_file)
    else:
        dataset_images = {}

    dataset_images[keyword] = data

    with open(DATASET_NAME, 'w', encoding = 'utf-8') as writeable_file:
        json.dump(dataset_images, writeable_file)


def download_images(keyword: str, image_urls: list[dict]):
    kategory_images = []
    with ThreadPoolExecutor() as executor:
        futures = []
        for url in image_urls:
            f = executor.submit(download_file, url)
            futures.append(f)

        for future in as_completed(futures):
            resized_image = future.result()

            if resized_image is not None:
                kategory_images.append(resized_image)

    if len(kategory_images) < 2:
        return

    set_keyword(keyword, kategory_images)

def main():
    keywords_number = DATASET_SIZE[1]
    if keywords_number > len(KEYWORDS):
        keywords_number = len(KEYWORDS)

    choosen_keywords = []
    for _ in range(keywords_number):
        random_keyword = random.choice(KEYWORDS)
        while random_keyword in choosen_keywords:
            random_keyword = random.choice(KEYWORDS)

        choosen_keywords.append(random_keyword)

        found_images = DDGS().images(
            keywords = random_keyword, type_image='photo', max_results = DATASET_SIZE[0]
        )
        image_urls = [
            image['image'] for image in found_images
            if random_keyword in image['title']
        ]

        download_images(random_keyword, image_urls)

if __name__ == '__main__':
    main()
