import os
from typing import Final
from duckduckgo_search import DDGS
from utils import JSON, download_images


DATASET_NAME: Final[str] = 'keys.json'
DATASET_SIZE: Final[tuple[int]] = (200, 50)
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

ANIMALS: Final[list] = [
    'Dog','Cat','Bird','Fish','Rabbit','Mouse','Horse','Cow',
    'Pig','Sheep','Chicken','Duck','Goose','Turkey','Deer','Bear',
    'Fox','Squirrel','Raccoon','Elephant','Giraffe','Lion','Tiger',
    'Cheetah','Leopard','Zebra','Hippopotamus','Rhino','Gorilla',
    'Chimpanzee','Orangutan','Koala','Kangaroo','Platypus','Dolphin',
    'Whale','Shark','Octopus','Squid','Jellyfish','Turtle','Frog',
    'Toad','Salamander','Newt','Lizard','Snake','Crocodile','Alligator',
    'Tortoise'
]

DATASET: Final[dict] = KEYWORDS
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_FILE_PATH = os.path.join(DATASET_NAME, CURRENT_DIR)


def main():
    """
    Downloads images from the DuckDuckGo Image Search API and saves them to a
    JSON file.

    The number of images downloaded and the number of keywords used are
    determined by the variables DATASET_SIZE and OTHER_KEYWORDS, respectively.

    The downloaded images are saved to a JSON file named 'custom.json'.
    """

    image_count, keyword_count = DATASET_SIZE

    keywords = DATASET[:min(keyword_count, len(DATASET))]
    for keyword in keywords:
        searched_images = DDGS().images(
            keywords = keyword + ' images',
            type_image = 'photo', max_results = image_count
        )

        image_urls = [
            image["image"] for image in searched_images
            if keyword.lower() in image["title"]
        ]

        download_images(DATASET_FILE_PATH, keyword, image_urls)


if __name__ == '__main__':
    if not os.path.isfile(DATASET_FILE_PATH):
        main()

    keywords_to_images: dict = JSON.load(DATASET_FILE_PATH, default = {})

    images = []
    for imageset in keywords_to_images.values():
        images += imageset

    print(f"Loaded {len(images)} images from {DATASET_NAME}.")
