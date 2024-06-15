import os
from io import BytesIO
from typing import Final
import torch
from diffusers import DiffusionPipeline
from utils import Block, JSON, resize_image, get_random_image, convert_image_to_base64

DATASET_NAME: Final[str] = 'ai-dogs.json'
DATASET_SIZE: Final[tuple[int]] = (100, 50)
# the first number indicates how many images are downloaded per keyword
# the second number indicates how many keywords can be used

DOG_KEYWORDS = ['smiling dog', 'not smiling dog']

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

DATASET: Final[dict] = DOG_KEYWORDS
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_FILE_PATH: Final[str] = os.path.join(CURRENT_DIR, DATASET_NAME)


def generate_ai_image(pipe: DiffusionPipeline, about: str) -> bytes:
    """
    Generate an image using the given pipe and about information.

    :param pipe: The pipe to use for generating the image.
    :param about: The about information for the image.
    :return: The generated image as bytes.
    """

    prompt = 'a photo of a ' + about
    image = pipe(prompt=prompt).images[0]

    buffer = BytesIO()
    image.save(buffer, format="PNG")
    image_bytes = buffer.getvalue()

    return image_bytes


def get_pipe() -> DiffusionPipeline:
    """
    Returns a DiffusionPipeline instance with the specified settings.

    The device to use is determined by torch.cuda.is_available().

    If cuda is available, a DiffusionPipeline instance with float16 torch_dtype
    is returned. If cuda is not available, a DiffusionPipeline instance with
    float32 torch_dtype is returned, and the device is set to 'cpu'.

    :return: A DiffusionPipeline instance.
    """

    device = 'cuda' if torch.cuda.is_available() else 'cpu'

    try:
        pipe = DiffusionPipeline.from_pretrained(
            "stabilityai/stable-diffusion-xl-base-1.0",
            torch_dtype=torch.float16,
            use_safetensors=True,
            variant="fp16",
            device=device
        )
    except RuntimeError as e:
        print(f"Cuda not available: {e}")
        pipe = DiffusionPipeline.from_pretrained(
            "stabilityai/stable-diffusion-xl-base-1.0",
            torch_dtype=torch.float32,
            use_safetensors=True,
            variant="fp16",
            device="cpu"
        )

    pipe.to(device)

    return pipe


def main() -> None:
    """
    Generates a dataset of images based on keywords and saves them to a JSON file.

    The number of images downloaded and the number of keywords used are
    determined by the variables DATASET_SIZE and DATASET, respectively.

    The downloaded images are saved to a JSON file named 'custom.json'.
    """

    image_count, keyword_count = DATASET_SIZE

    if DATASET == DOG_KEYWORDS:
        image_count = image_count * 25

    pipe = None

    keywords = DATASET[:min(keyword_count, len(DATASET))]
    for keyword in keywords:
        file_name_keyword = os.path.join(CURRENT_DIR, keyword.replace(' ', '_') + '.json')
        block = Block(file_path=file_name_keyword)

        if block.size >= image_count:
            continue

        for i in range(image_count - block.size):
            if pipe is None:
                pipe = get_pipe()

            image = generate_ai_image(pipe, keyword)
            image = resize_image(image)
            block.add_data(i, image)

    complete_data = {}

    for keyword in keywords:
        file_name_keyword = os.path.join(CURRENT_DIR, keyword.replace(' ', '_') + '.json')
        complete_data[keyword] = JSON.load(file_name_keyword, [])
        #os.remove(file_name_keyword)

    JSON.dump(complete_data, DATASET_FILE_PATH)


if __name__ == '__main__':
    main()

    keywords_to_images: dict = JSON.load(DATASET_FILE_PATH, default = {})

    images = []
    for imageset in keywords_to_images.values():
        images += imageset

    print(f"Loaded {len(images)} images from {DATASET_NAME}.")

    while True:
        random_smiling_dog = get_random_image(keywords_to_images['smiling dog'])
        print(convert_image_to_base64(random_smiling_dog))

        input('Press enter to generate another image...')
