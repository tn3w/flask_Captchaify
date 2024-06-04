"""
⭐ Example code for flask_Captchaify

https://github.com/tn3w/flask_Captchaify
Made with 💩 in Germany by TN3W
"""

from flask import Flask
from flask_Captchaify import Captchaify

app = Flask(__name__)
captchaify = Captchaify(app)

@app.route('/')
def index():
    """
    Very good protected Route
    """

    return 'Hello human!🖐️'

if __name__ == '__main__':
    app.run(host = 'localhost', port = 9000)
