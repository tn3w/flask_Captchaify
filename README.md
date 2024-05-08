<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/tn3w/flask_Captchaify/releases/download/img_v1.7/oneclick_dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/tn3w/flask_Captchaify/releases/download/img_v1.7/oneclick_light.png">
  <img alt="Picture from Block Page" src="https://github.com/tn3w/flask_Captchaify/releases/download/img_v1.7/oneclick_light.png">
</picture>
<p align="center"><a rel="noreferrer noopener" href="https://github.com/tn3w/flask_Captchaify"><img alt="Github" src="https://img.shields.io/badge/Github-141e24.svg?&style=for-the-badge&logo=github&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://pypi.org/project/flask-Captchaify/"><img alt="PyPI" src="https://img.shields.io/badge/PyPi-141e24.svg?&style=for-the-badge&logo=python&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://libraries.io/pypi/flask-Captchaify"><img alt="Libraries.io" src="https://img.shields.io/badge/Libraries.io-141e24.svg?&style=for-the-badge&logo=npm&logoColor=white"></a>

# flask_Captchaify
A DDoS defense system for flask applications, first sends users to a captcha page without a javascript script and creates a confirmation cookie/url arg after the captcha.

> [!CAUTION]
> Captchaify must now no longer be imported as Captcha, i.e. `from flask_Captchaify import Captcha`, but as Captchaify (`from flask_Captchaify import Captchaify`)
> The normal captcha page has changed and from version 1.6.8 uses a one-click method instead of text captchas
> Use the `default_captcha_type` argument to set the captcha with `text` back to text

Todos:
- [ ] Captcha type with animals or emojis
- [ ] Captcha type with multiclick
- [ ] Add used captcha id to text captcha
- [ ] Captcha or blocking rules based on client_ip and client_ip_info (e.g. blocking of certain IP countries)

## How does flask_Captchaify work?
If needed, a captcha is displayed to the user (or the robot) based on the strength set.[^1] Javascript is not needed for this, as the content is rendered on the server.[^2]

An example script could look like this:
```python
from flask import Flask
from flask_Captchaify import Captchaify

app = Flask(__name__)
captchaify = Captchaify(app, default_action = "fight")

@app.route("/")
def index():
    return 'Hello Human!'

if __name__ == "__main__":
    app.run(host = "localhost", port = 8080)
```

## Application purposes
A few application purposes:
  - Protect against DDoS attacks [^3]
  - Your website contains content that should not be read by a robot
  - A login website
  - A dark web page

### Why should you use Captchaify if you host a Flask server?
A quick and easy implementation allows even small websites or a small team of developers to quickly get bot protection. It also doesn't use third-party providers, which limits data collection from Google, Facebook and the creepy data brokers.[^4] Everything is open source, meaning you can rewrite the code yourself and perhaps make it more private.

# Instructions

## Installation guide
1. Make sure you have the latest version of Python and Pip installed, you also need git installed.
2. Install the script with pip `pip install flask_Captchaify` or manually via `git clone https://github.com/tn3w/flask_Captchaify` or download the zip.
3. If you installed it manually, make sure your python script is in the folder where there is a subfolder flask_Captchaify, and make sure you run `pip install -r requirements.txt` in the flask_Captchaify folder.
5. Make sure that after:
   ```python
   app = Flask(__name__)
   ```
   You add the line:
   ```python
   captchaify = Captchaify(app, default_action = "fight")
   ```
   And at the beginning of the file add the import:
   ```python
   from flask_Captchaify import Captchaify
   ```
For more information, see the sample code above.

## Personalization
1. `app` Arg

   A Flask() object of a Flask app that is modified by Captchaify so that each request is checked for bots

   Example:
   ```python
   from flask import Flask
   from flask_Captchaify import Captchaify

   app = Flask('MyWebsite')
   captchaify = Captchaify(app)
   ```


2. `captcha_types` Arg

   To change the captcha type in the case of certain routes / endpoints, you can use the captcha_types parameter.
   
   Example of a website that uses an oneclick captcha on the main page and enforces text captchas on the login page.
   ```python
   captchaify = Captchaify(app, captcha_types={"/": "oneclick", "/login": "text"})
   ```

   When using "*" before or after the urlpath / endpoint you can address multiple urls.

   Example of a website where all urls with /dev/ are using oneclick captchas, all urls starting with "/login/" displays an text based captcha and all urls ending with "/register/" have oneclick captchas:
   ```python
   captchaify = Captchaify(app, captcha_types={"*/dev/*": "oneclick", "/login/*": "text", "*/register/": "oneclick"})
   ```
   
   All captcha types:
   | Name of captcha type | Displayed Captchas                                                       |
   | --------------       | ------------------------------------------------------------------------ |
   | oneclick (Default)   | The user only needs one click to confirm that he is not a bot            |
   | text                 | The user enters a text combination from an image into an input (obsolete)|


3. `dataset_size` Arg

   The size of the data set with e.g. images and keywords that determine how much of a data set is used, if a lot is used this can reduce RAM capacity but also increase security
   Either a tuple of 2 numbers where the first indicates how many images per keyword (always the first ones) can be used (recommended around 20, maximum 200 or more depending on the data set) and the second number how many keywords are e.g. (images_per_keyword, number_of_keywords), default setting: (20, 100)

   But can also be a string for prefabricated dimensions:
   | value             | corresponding tuple |
   | ----------------- | ------------------- |
   | largest           | (200, 140)          |
   | large             | (20, 140)           |
   | medium            | (100, 100)          |
   | normal (default)  | (20, 100)           |
   | small             | (20, 36)            |
   | smaller           | (20, 8)             |
   | little            | (6, 8)              |

   The more images per keyword, the more inaccurate the user rate becomes, as images further behind in the image search and in the data set could no longer show the keyword
   It is recommended that you generate your own dataset as the default data could be trained, use the script written in src/flask_Captchaify/datasets and put the file in a folder and use the `dataset_dir` arg to use it

   Example of a website that uses 100 images per keyword and 140 keywords:
   ```python
   captchaify = Captchaify(app, dataset_size=(100, 140))
   ```


4. `dataset_dir` Arg

   Specifies where the program can find data sets.

   Example of a website that specifies its own dataset folder:
   ```python
   captchaify = Captchaify(app, dataset_dir='/path/to/my/dataset')
   ```

   A data set should be a json file and have the following names in the folder:
   ```
   dataset_dir\
          \oneclick_keys.json
   ```


5. `actions` Arg

   To change the response in the case of certain routes / endpoints, you can use the actions parameter.
   
   Example of a website that allows all bots on the main page, enforces captchas on the login page, and blocks all robots on the registration page:
   ```python
   captchaify = Captchaify(app, actions={"/": "let", "/login": "fight", "/register": "block"})
   ```

   When using "*" before or after the urlpath / endpoint you can address multiple urls.

   Example of a website where all urls with /api/ are allowed through, all urls starting with "/dogs/" show everyone a captcha and all urls ending with "/cats/" block bots:
   ```python
   captchaify = Captchaify(app, actions={"*/api/*": "let", "/dogs/*": "fight", "*/cats/": "block"})
   ```
   
   All actions:
   | Name of action | Executing Action                                                     |
   | -------------- | -------------------------------------------------------------------- |
   | let            | Allows all traffic through, regardless of whether the IP is blocked. |
   | block          | Blocks all traffic if it is blocked, without captcha.                |
   | fight          | Displays a captcha to all traffic, whether suspicious or not.        |
   | captcha        | Default value, shows only suspicious traffic captchas.               |


6. `hardness` Arg
   
   To change the hardness of a captcha for specific routes or endpoints use hardness.

   Example of a website that sets the hardness of the main page to 1 (= easy), on the login page to 2 (= normal) and on the register page to 3 (= hard):
   ```python
   captchaify = Captchaify(app, hardness={"/": 1, "/login": 2, "/register": 3})
   ```

   When using "*" before or after the urlpath / endpoint you can address multiple urls, like actions.

   All hardness levels:
   | Hardness Level | Captcha modification                                                                                                               |
   | -------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
   | 1              | The captcha is easy. Only a text captcha with 6 - 8 characters is displayed                                                        |
   | 2              | The captcha is normal. Only a text captcha with 9 - 11 characters is displayed                                                     |
   | 3              | The hardness of the captcha is hard, a 9 - 14 number audio captcha is displayed in addition to the 10 - 12 character text captcha. |


7. `rate_limits` Arg

   To change the rate_limit and max_rate_limit for a specific route or endpoint use the rate_limits arg.
   The syntax is a bit different from the others, because two values are specified `{"route": (rate_limit, max_rate_limit), "endpoint": (rate_limit, max_rate_limit)}`. The variable rate_limit must be a number indicating how many requests per minute can come from a given ip. max_rate_limit indicates how many requests can come from all ips per minute, also a number.

   Example of a website that has a specific rate_limit on /api/:
   ```python
   captchaify = Captchaify(app, template_dirs={"/api/*": (60, 600)})
   ```


8. `template_dirs` Arg

   To change the template directory of a particular route use the template_dirs arg.

   Example of a website that has a specific template directory on /api/:
   ```python
   captchaify = Captchaify(app, template_dirs={"/api/*": "/path/to/special/template/directory"})
   ```

   A template directory can look like this:
   ```
   template_directory\
              \captcha_text.html
              \captcha_oneclick.html
              \captcha_multiclick.html
              \block.html
              \rate_limited.html
              \change_language.html
   ```

   If one of the three templates does not exist in the folder, a 404 error is displayed when calling it. e.g. if you remove the changelanguage page at apis.

9. `default_captcha_type` Arg

   To specify the default captcha type of all routes or endpoints use the default_captcha_type arg.

   Example of a website that has set its types to "text" (for text bases captchas) for all routes:
   ```python
   captchaify = Captchaify(app, default_captcha_type="text")
   ```

9. `default_action` Arg

   To specify the default action of all routes or endpoints use the default_action arg.

   Example of a very paranoid website that has set its action to "fight" for all routes:
   ```python
   captchaify = Captchaify(app, default_action="fight")
   ```


9. `default_hardness` Arg

   To specify the default hardness of all routes or endpoints use the default_hardness arg.

   Example of a very paranoid website that has set its hardness to 3 (= hard) for all routes:
   ```python
   captchaify = Captchaify(app, default_hardness=3)
   ```

9. `default_rate_limit` Arg

   To specify the default requests of an IP per minute for all routes use the default_rate_limit variable. (Default: 120 = 2 requests per second per IP)

   Example of a web page with custom rate_limit:
   ```python
   captchaify = Captchaify(app, default_rate_limit=60)
   ```

9. `default_max_rate_limit` Arg

   To specify the default requests of all IPs per minute for all routes use the default_max_rate_limit variable. (Default: 1200 = 2 requests per second from 10 IPs)

   Example of a web page with custom max_rate_limit:
   ```python
   captchaify = Captchaify(app, default_max_rate_limit=600)
   ```


9. `default_template_dir` Arg

   To specify the default template_dir of all routes or endpoints use the default_template_dir arg.

   Example of a web page with custom template_dir:
   ```python
   captchaify = Captchaify(app, default_template_dir="/path/to/my/custom/template/directory")
   ```


9. `verification_age` Arg

   Indicates the time in seconds how long a solved captcha is valid (Default: 3600 = 1 hour)

   Website with 3 hours verification_age:
   ```python
   captchaify = Captchaify(app, verification_age=10800)
   ```


9. `without_cookies` Arg

   If True, no cookies are created, and verification is proven via URL args (Default: False)

   Website with without_cookies enabled:
   ```python
   captchaify = Captchaify(app, without_cookies=True)
   ```


9. `block_crawler` Arg

   If True, crawlers like Googlebot, further are estimated via their user agent as suspicious and not the website, good for websites that should not be crawled (Default: True)

   Web page with block_crawler enabled:
   ```python
   captchaify = Captchaify(app, block_crawler=True)
   ```


9. `crawler_hints` Arg:

   If True, crawlers like Googlebot, are shown meta tags and the title of a normal web page, while they would have to solve a captcha. (Default: True)
   
   Web page with crawler_hints disabled:
   ```python
   captchaify = Captchaify(app, crawler_hints=False)
   ```


9. `third_parties` Arg:

   Specifies which third parties are used to check the IP addresses. By default, all 3 third parties are used. (See list)

   Web page that only asks a third party for Tor Ip addresses:
   ```python
   captchaify = Captchaify(app, third_parties=["tor"])
   ```

   Possible entries would be:
   | Abbreviation         | Who is requested and how does the evaluation mechanism work?                                                                           |
   | -------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
   | tor                  | [SecOps-Institute/Tor-IP-Addresses](https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst) on GitHub is asked for Tor Ipv4 and Ipv6 addresses and the Ip address is compared with this list |
   | ipapi                | [Ipapi](https://ipapi.com) is requested with the Ip and the result of the fields "proxy" and "hosting" is used                                              |
   | stopforumspam        | [StopForumSpam](https://stopforumspam.com) is requested and the result is used                                                         |



[^1]: Text and, if the set strength is above 2, audio captchas can already be partially solved by robots, this is a solution for small websites or, e.g. dark web sites that cannot use third party solutions. However, it should still provide sufficient protection.
[^2]: For a captcha to work, however, the user's IP and user agent must normally be stored. The website may also collect data such as language to translate the website. Cookies can also be used, this is decided by the server administrator.
[^3]: Only if you have a large server that is supposed to protect a small server from DDoS attacks.
[^4]: Only if you do not use other services such as Google Analytics/Meta Pixel on your website.
