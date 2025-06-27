<h1 align="center">flask-Humanify</h1>
<p align="center">A strong bot protection system for Flask with many features: rate limiting, special rules for users, web crawler detection, and automatic bot detection.</p>
<p align="center"><a rel="noreferrer noopener" href="https://github.com/tn3w/flask-Humanify"><img alt="Github" src="https://img.shields.io/badge/Github-141e24.svg?&style=for-the-badge&logo=github&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://pypi.org/project/flask-Humanify/"><img alt="PyPI" src="https://img.shields.io/badge/PyPi-141e24.svg?&style=for-the-badge&logo=python&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://libraries.io/pypi/flask-Humanify"><img alt="Libraries.io" src="https://img.shields.io/badge/Libraries.io-141e24.svg?&style=for-the-badge&logo=npm&logoColor=white"></a></p>

<br>

```python
from flask import Flask
from flask_Humanify import Humanify

app = Flask(__name__)
humanify = Humanify(app)

@app.route("/")
def index():
    """
    A route that is protected against bots and DDoS attacks.
    """
    if humanify.is_bot:
        return humanify.redirect_to_access_denied()
    return "Hello, Human!"

if __name__ == "__main__":
    app.run()
```

## Usage

### Installation
Install the package with pip:
```bash
pip install flask-humanify --upgrade
```

Import the extension:
```python
from flask_humanify import Humanify
```

Add the extension to your Flask app:
```python
app = Flask(__name__)
humanify = Humanify(app)
```