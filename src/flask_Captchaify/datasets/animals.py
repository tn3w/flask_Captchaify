import os
import random
import json
import time
from io import BytesIO
import gzip
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Final
from duckduckgo_search import DDGS
import requests
from PIL import Image


DATASET_NAME: Final[str] = 'custom.json'
DATASET_SIZE: Final[tuple[int]] = (200, 50)
# the first number indicates how many images are downloaded per keyword
# the second number indicates how many keywords can be used

OTHER_KEYWORDS: Final[list] = [
    "Dog","Cat","Bird","Fish","Rabbit","Mouse","Horse","Cow",
    "Pig","Sheep","Chicken","Duck","Goose","Turkey","Deer","Bear",
    "Fox","Squirrel","Raccoon","Elephant","Giraffe","Lion","Tiger",
    "Cheetah","Leopard","Zebra","Hippopotamus","Rhino","Gorilla",
    "Chimpanzee","Orangutan","Koala","Kangaroo","Platypus","Dolphin",
    "Whale","Shark","Octopus","Squid","Jellyfish","Turtle","Frog",
    "Toad","Salamander","Newt","Lizard","Snake","Crocodile","Alligator",
    "Tortoise"
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
            time.sleep(0.2)

        for future in as_completed(futures):
            resized_image = future.result()

            if resized_image is not None:
                kategory_images.append(resized_image)

    if len(kategory_images) < 2:
        return

    set_keyword(keyword, kategory_images)


def download_dog():
    try:
        resp = requests.get('https://dog.ceo/api/breeds/image/random', headers = HEADER, timeout=10)
        resp.raise_for_status()

        data = resp.json()
        image_url = data['message']
        resized_image = download_file(image_url)
        return resized_image
    except Exception as e:
        print(e)


KEYWORDS: Final[dict[str]] = {
    "cat": "https://cataas.com/cat",
    "dog": download_dog,
}

def main():
    keywords_number = DATASET_SIZE[1]
    if keywords_number > len(OTHER_KEYWORDS):
        keywords_number = len(OTHER_KEYWORDS)

    choosen_keywords = []
    for _ in range(keywords_number):
        random_keyword = random.choice(OTHER_KEYWORDS)
        while random_keyword in choosen_keywords:
            random_keyword = random.choice(OTHER_KEYWORDS)

        random_keyword = random_keyword.lower()

        choosen_keywords.append(random_keyword)

        if random_keyword in list(KEYWORDS.keys()):
            if isinstance(KEYWORDS[random_keyword], str):
                image_urls = [KEYWORDS[random_keyword]] * DATASET_SIZE[0]
                download_images(random_keyword, image_urls)
            else:
                images = []
                for i in range(DATASET_SIZE[0]):
                    new_image = KEYWORDS[random_keyword]()
                    if not new_image is None:
                        images.append(new_image)
                    time.sleep(0.2)
                set_keyword(random_keyword, images)
        else:
            found_images = DDGS().images(
                keywords = random_keyword + " images", type_image='photo', max_results = DATASET_SIZE[0]
            )
            image_urls = [
                image['image'] for image in found_images
                if random_keyword in image['title']
            ]

            download_images(random_keyword, image_urls)


if __name__ == '__main__':
    main()
