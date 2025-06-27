import hashlib
import time
from collections import defaultdict, deque

from flask import request, redirect, url_for, render_template
from flask_Humanify.utils import get_client_ip, get_return_url


class RateLimiter:
    """
    Rate limiter.
    """

    def __init__(self, app=None, max_requests: int = 2, time_window: int = 10):
        """
        Initialize the rate limiter.
        """
        self.app = app
        if app is not None:
            self.init_app(app)
        self.max_requests = max_requests
        self.time_window = time_window
        self.ip_request_times = defaultdict(deque)

    def init_app(self, app):
        """
        Initialize the rate limiter.
        """
        self.app = app
        self.app.before_request(self.before_request)

        @self.app.route(
            "/humanify/rate_limited",
            methods=["GET"],
            endpoint="humanify.rate_limited",
        )
        def rate_limited():
            """
            Rate limited route.
            """
            return (
                render_template("rate_limited.html").replace(
                    "RETURN_URL", get_return_url(request)
                ),
                429,
                {"Cache-Control": "public, max-age=15552000"},
            )

    def before_request(self):
        """
        Before request hook.
        """
        ip = get_client_ip(request)
        if request.endpoint == "humanify.rate_limited":
            return
        if self.is_rate_limited(ip or "127.0.0.1"):
            return redirect(
                url_for("humanify.rate_limited", return_url=request.full_path)
            )

    def is_rate_limited(self, ip: str) -> bool:
        """
        Check if the IP is rate limited.
        """
        hashed_ip = hashlib.sha256(ip.encode()).hexdigest()

        current_time = time.time()
        request_times = self.ip_request_times[hashed_ip]

        while request_times and request_times[0] <= current_time - self.time_window:
            request_times.popleft()

        if len(request_times) < self.max_requests:
            request_times.append(current_time)
            return False

        return True
