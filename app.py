from flask import Flask
from flask_humanify import Humanify, RateLimiter

app = Flask(__name__)
humanify = Humanify(app, challenge_type="grid", captcha_dataset="ai_dogs")
humanify.register_middleware()
rate_limiter = RateLimiter(app)


@app.route("/")
def index():
    """
    Protect against bots and DDoS attacks.
    """
    return "Hello, Human!"


if __name__ == "__main__":
    app.run(debug=True)
