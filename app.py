from flask import Flask
from flask_humanify import Humanify

app = Flask(__name__)
humanify = Humanify(app)


@app.route("/")
def index():
    """
    Protect against bots and DDoS attacks.
    """
    if humanify.is_bot:
        return humanify.deny_access()
    return "Hello, Human!"


if __name__ == "__main__":
    app.run(debug=True)
