"""
trueclick.py

This module implements a TrueClick captcha system, designed to verify user interactions 
and distinguish between human and automated submissions. It calculates human scores 
based on user behavior and generates captcha challenges using image datasets.

License:
Made available under the GPL-3.0 license.
"""

import os
import secrets
from time import time
import urllib.request
from typing import Optional, Tuple
from flask import request
import numpy as np
from .utils import (
    DATASETS_DIR, DATA_DIR, JSON, PICKLE, get_random_image,
    convert_image_to_base64, manipulate_image_bytes, generate_random_string
)
from .cryptograph import Hashing


HASHING = Hashing(20000)
CAPTCHAS_FILE_PATH = os.path.join(DATA_DIR, 'trueclick.pkl')


def calculate_human_score(interaction_data: dict) -> float:
    """
    Calculate the human score based on an interaction data.

    Args:
        interaction_data (dict): he interaction data.

    Returns:
        float: The human score.
    """

    mouse_movements = interaction_data.get('mouseMovements', [])
    clicks = interaction_data.get('clicks', [])
    form_inputs = interaction_data.get('formInputs', [])

    if not mouse_movements or not clicks:
        return 1.0

    movement_times = [movement['timestamp'] for movement in mouse_movements]
    click_times = [click['timestamp'] for click in clicks]
    input_times = [input['timestamp'] for input in form_inputs]

    all_times = movement_times + click_times + input_times
    all_times.sort()

    intervals = np.diff(all_times)

    if len(intervals) == 0:
        return 1.0

    mean_interval = np.mean(intervals)
    std_interval = np.std(intervals)

    human_score = (1.0 - (std_interval / mean_interval)) if mean_interval > 0 else 1.0
    human_score = max(0.0, min(1.0, human_score))

    return human_score


class TrueClick:
    """
    A class for generating true click captchas.
    """


    def __init__(self, dataset_dir: str = DATASETS_DIR, hardness: int = 1) -> None:
        """
        Initialize the TrueClick instance.

        Args:
            dataset_dir (str): The directory where datasets are stored.
            hardness (int): The hardness level for the captcha.
        """

        self.dataset_dir = dataset_dir
        self.hardness = hardness
        self.loaded_datasets = {}

        self._download_datasets()


    def _download_datasets(self) -> None:
        """
        Download the datasets if they haven't already been downloaded.
        """

        if not os.path.exists(self.dataset_dir):
            os.mkdir(self.dataset_dir)

        for url in [
            ("https://raw.githubusercontent.com/tn3w/"
             "Captcha_Datasets/refs/heads/master/datasets/keys.pkl"),
            ("https://raw.githubusercontent.com/tn3w/"
             "Captcha_Datasets/refs/heads/master/datasets/animals.pkl"),
            ("https://raw.githubusercontent.com/tn3w/"
             "Captcha_Datasets/refs/heads/master/datasets/ai-dogs.pkl")
            ]:

            file_name = url.rsplit('/', maxsplit=1)[-1]
            file_path = os.path.join(self.dataset_dir, file_name)

            if not os.path.exists(file_path):
                print('Downloading', file_name)
                urllib.request.urlretrieve(url, file_path)


    def _load_dataset(self, dataset_path: str) -> dict:
        """
        Load a dataset from the specified path.

        Args:
            dataset_path (str): The path to the dataset.

        Returns:
            Dict[str, Any]: The loaded dataset.
        """

        if dataset_path in self.loaded_datasets:
            return self.loaded_datasets[dataset_path]

        dataset = PICKLE.load(dataset_path)

        self.loaded_datasets[dataset_path] = dataset
        return dataset


    #########################
    #### Captcha Storage ####
    #########################


    def _load(self) -> dict:
        """
        Load the captcha data from the file.

        Returns:
            Dict[str, Any]: The loaded captcha data.
        """

        captchas = PICKLE.load(CAPTCHAS_FILE_PATH)

        cleaned_captchas = {}
        for captcha_id, captcha in captchas.items():
            if int(time()) - captcha['time'] <= 720:
                cleaned_captchas[captcha_id] = captcha

        return cleaned_captchas


    def add_captcha(self, data: dict) -> Tuple[str, str]:
        """
        Add a captcha to the file.

        Args:
            data (Dict[str, Any]): The captcha data.

        Returns:
            Tuple[str, str]: A tuple containing the captcha id and token.
        """

        captcha_id = generate_random_string(8, with_punctuation=False)
        while self.captcha_exists(captcha_id):
            captcha_id = generate_random_string(8, with_punctuation=False)

        captcha_token = generate_random_string(12)

        captcha = {
            'htoken': Hashing().hash(captcha_token),
            'data': data,
            'time': int(time())
        }

        captchas = self._load()
        captchas[captcha_id] = captcha

        PICKLE.dump(captchas, CAPTCHAS_FILE_PATH)

        return captcha_id, captcha_token


    def captcha_exists(self, captcha_id: str) -> bool:
        """
        Check if a captcha exists in the file.

        Args:
            captcha_id (str): The id of the captcha.

        Returns:
            bool: True if the captcha exists, False otherwise.
        """

        captchas = self._load()
        return captcha_id in captchas


    def get_captcha(self, captcha_id: str) -> Optional[dict]:
        """
        Get a captcha from the file.

        Args:
            captcha_id (str): The id of the captcha.

        Returns:
            Optional[Dict[str, Any]]: The captcha data, or None if it doesn't exist.
        """

        captchas = self._load()
        return captchas.get(captcha_id, None)


    def remove_captcha(self, captcha_id: str) -> None:
        """
        Remove a captcha from the file.

        Args:
            captcha_id (str): The id of the captcha.
        """

        captchas = self._load()

        if captcha_id in captchas:
            del captchas[captcha_id]

            PICKLE.dump(captchas, CAPTCHAS_FILE_PATH)


    def is_trueclick_valid(self) -> bool:
        """
        Verify the trueclick captcha based on a Flask request.

        Returns:
            bool: True if the captcha is verified, False otherwise.
        """

        data = request.form if request.method.lower() == 'post' else request.args

        if not isinstance(data, dict):
            return False

        captcha_id_token = data.get('trueclick_response', None)
        if not captcha_id_token:
            return False

        captcha_id, captcha_token = captcha_id_token[:8], captcha_id_token[8:]

        return self.is_captcha_verified(captcha_id, captcha_token)


    def is_captcha_verified(self, captcha_id: str, captcha_token: str) -> bool:
        """
        Verify a captcha.

        Args:
            captcha_id (str): The id of the captcha.
            captcha_token (str): The token of the captcha.

        Returns:
            bool: True if the captcha is verified, False otherwise.
        """

        captcha = self.get_captcha(captcha_id)

        if not captcha or not Hashing().compare(captcha_token, captcha['htoken']):
            return False

        is_verified = captcha.get('verified', False)

        if is_verified:
            self.remove_captcha(captcha_id)

        return is_verified


    def is_captcha_token_valid(self, captcha_id: str, captcha_token: str) -> bool:
        """
        Verify a captcha token.

        Args:
            captcha_id (str): The id of the captcha.
            captcha_token (str): The token of the captcha.

        Returns:
            bool: True if the captcha token is valid, False otherwise.
        """

        captcha = self.get_captcha(captcha_id)

        if not Hashing().compare(captcha_token, captcha['htoken']):
            return False

        return True


    def verify_captcha(self, captcha_id: str, captcha_token: str, selected_indices: list) -> bool:
        """
        Verify a captcha.

        Args:
            captcha_id (str): The id of the captcha.
            captcha_token (str): The token of the captcha.
            selected_indices (List[int]): The indices of the selected characters.

        Returns:
            bool: True if the captcha is verified, False otherwise.
        """

        if not self.is_captcha_token_valid(captcha_id, captcha_token):
            return False

        captcha = self.get_captcha(captcha_id)
        if sorted(selected_indices) != sorted(captcha['data']['correct']):
            self.remove_captcha(captcha_id)
            return False

        captcha['verified'] = True
        self.remove_captcha(captcha_id)

        captchas = self._load()
        captchas[captcha_id] = captcha

        PICKLE.dump(captchas, CAPTCHAS_FILE_PATH)

        return True

    ###################
    #### Generator ####
    ###################


    def generate_captcha(self, dataset_name: str) -> dict:
        """
        Generate a captcha for the client.

        Args:
            dataset_name (str): The name of the dataset to use.

        Returns:
            Dict[str, Any]: The generated captcha data including id, token,
                original image, and images list.
        """

        if not dataset_name.endswith('.pkl'):
            dataset_name += '.pkl'

        dataset = self._load_dataset(os.path.join(self.dataset_dir, dataset_name))["keys"]

        captcha_data = {}

        keywords = list(dataset.keys())
        if 'smiling dog' in keywords and len(keywords) == 2:
            keyword = 'smiling dog'
        else:
            keyword = secrets.choice(keywords)

        captcha_data['keyword'] = keyword

        images = dataset[keyword]
        original_image = get_random_image(images)

        num_originals = secrets.choice([2, 3, 4])
        other_keywords = [keyword] * num_originals

        while len(other_keywords) < 9:
            random_keyword = secrets.choice(keywords)
            if random_keyword != keyword and\
                (random_keyword not in other_keywords or len(keywords) == 2):

                other_keywords.append(random_keyword)

        secrets.SystemRandom().shuffle(other_keywords)

        captcha_data['correct'] = [i for i, k in enumerate(other_keywords) if k == keyword]

        captcha_images = []
        for keyword in other_keywords:
            images = dataset[keyword]

            random_image = get_random_image(images)
            while random_image in captcha_images or random_image == original_image:
                random_image = get_random_image(images)
            captcha_images.append(random_image)

        original_image = convert_image_to_base64(
            manipulate_image_bytes(original_image, hardness = self.hardness)
        )

        captcha_images = [
            convert_image_to_base64(
                manipulate_image_bytes(
                    image, is_small = True, hardness = self.hardness
                )
            ) for image in captcha_images
        ]
        captcha_images = [
            {'id': str(i), 'src': image_data}
            for i, image_data in enumerate(captcha_images)
        ]

        captcha_id, captcha_token = self.add_captcha(captcha_data)

        return {
            'id': captcha_id,
            'token': captcha_token,
            'original': original_image,
            'images': captcha_images
        }


if __name__ == "__main__":
    print("trueclick.py: This file is not designed to be executed.")
