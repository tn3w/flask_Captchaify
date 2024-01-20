from flask import Flask
from flask_Captchaify import Captcha

app = Flask(__name__)
captcha = Captcha(app, default_hardness=2, default_action = "fight")

@app.route("/")
def index():
    return 'Hello Human!'

if __name__ == "__main__":
    app.run(host = "localhost", port = 8080)