"""
Flask-Humanify
-----------
A Flask extension that protects against bots and DDoS attacks.
"""

__version__ = "0.1.1"

from . import utils
from .humanify import Humanify
from .features.rate_limiter import RateLimiter


__all__ = ["Humanify", "RateLimiter", "utils"]
