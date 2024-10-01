from flask import Flask
from src.flask_Captchaify.__init__ import Captchaify

app = Flask(__name__)
captchaify = Captchaify(app, captcha_type = "trueclick", dataset = "ai_dogs")

@app.route('/')
def index():
    """
    Extremely well protected route
    """

    return 'Hello human!🖐️'

if __name__ == '__main__':
    app.run(host = 'localhost', port = 9000)