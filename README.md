<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/tn3w/flask_DDoSify/releases/download/v0.3/blocked-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/tn3w/flask_DDoSify/releases/download/v0.3/blocked-light.png">
  <img alt="Picture from Block Page" src="https://github.com/tn3w/flask_DDoSify/releases/download/v0.3/blocked-dark.png">
</picture>
  
# flask_DDoSify
A DDoS defense system for flask applications, first sends users to a captcha page without a javascript script and creates a confirmation cookie/url arg after the captcha.

\[ \! \] With version 0.7 and 0.9 the syntax of the DDoSify() class has changed. \[ \! \]

## How does flask_DDoSify work?
Downloads public IP block lists[^1] and compares this data with the user, for more security the API of [Stop Forum Spam](https://www.stopforumspam.com/) is also used. If needed, a captcha is displayed to the user (or the robot) based on the strength set.[^2] Javascript is not needed for this, as the content is rendered on the server.[^3]

An example script could look like this:
```python
from flask import Flask
from flask_DDoSify.ddosify import DDoSify

app = Flask(__name__)
ddosify = DDoSify(app, default_hardness=2)

@app.route("/")
def index():
    return 'Hello Human!'

if __name__ == "__main__":
    app.run(host = "localhost", port = 8080)
```

> [!NOTE]
> 1. When testing DDoSify you should note that calling it from localhost gives the script a wrong IP in this case "127.0.0.1", which the script considers legitimate. When testing, use a service like cloudflared tunnel to connect to your script.
> 2. Note that when you first start the script, it first downloads and processes the block lists, which can take between 20 - 40 seconds. When you start the script again, the block lists are updated in the background.

## Application purposes
A few application purposes:
  - Protect against DDoS attacks [^4]
  - Your website contains content that should not be read by a robot
  - A login website
  - A dark web page that simply needs to be secured a bit

### Why should you use DDoSify if you host a Flask server?
A quick and easy implementation allows even small websites or a small team of developers to quickly get robot protection. It also doesn't use third-party providers, which limits data collection from Google, Facebook and the creepy data brokers.[^5] Everything is open source, meaning you can rewrite the code yourself and perhaps make it more private.

# Instructions

## Installation guide
1. Make sure you have the latest version of Python and Pip installed, you also need git installed.
2. Install the script with pip `pip install flask_DDoSify` or manually via `git clone https://github.com/tn3w/flask_DDoSify` or download the zip.
3. If you installed it manually, make sure your python script is in the folder where there is a subfolder flask_DDoSify, and make sure you run `pip install -r requirements.txt` in the flask_DDoSify folder.
5. Make sure that after:
   ```python
   app = Flask(__name__)
   ```
   You add the line:
   ```python
    ddosify = DDoSify(app)
   ```
   And at the beginning of the file add the import:
   ```python
   from flask_DDoSify.ddosify import DDoSify
   ```
For more information, see the sample code above.
## Personalization

1. `actions` Arg

   To change the response in the case of certain routes / endpoints, you can use the actions parameter.
   
   Example of a website that allows all bots on the main page, enforces captchas on the login page, and blocks all robots on the registration page:
   ```python
   ddosify = DDoSify(app, actions={"/": "let", "/login": "fight", "/register": "block"})
   ```

   When using "*" before or after the urlpath / endpoint you can address multiple urls.

   Example of a website where all urls with /api/ are allowed through, all urls starting with "/dogs/" show everyone a captcha and all urls ending with "/cats/" block bots:
   ```python
   ddosify = DDoSify(app, actions={"*/api/*": "let", "/dogs/*": "fight", "*/cats/": "block"})
   ```
   
   All actions:
   | Name of action | Executing Action                                                     |
   | -------------- | -------------------------------------------------------------------- |
   | let            | Allows all traffic through, regardless of whether the IP is blocked. |
   | block          | Blocks all traffic if it is on a block list, without captcha.        |
   | fight          | Displays a captcha to all traffic, whether suspicious or not.        |
   | captcha        | Default value, shows only suspicious traffic captchas.               |
   <br>

2. `hardness` Arg
   
   To change the hardness of a captcha for specific routes or endpoints use hardness.

   Example of a website that sets the hardness of the main page to 1 (= easy), on the login page to 2 (= normal) and on the register page to 3 (= hard):
   ```python
   ddosify = DDoSify(app, hardness={"/": 1, "/login": 2, "/register": 3})
   ```

   When using "*" before or after the urlpath / endpoint you can address multiple urls, like actions.

   All hardness levels:
   | Hardness Level | Captcha modification                                                                                                               |
   | -------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
   | 1              | The captcha is easy. Only a text captcha with 6 - 8 characters is displayed                                                        |
   | 2              | The captcha is normal. Only a text captcha with 9 - 11 characters is displayed                                                     |
   | 3              | The hardness of the captcha is hard, a 9 - 14 number audio captcha is displayed in addition to the 10 - 12 character text captcha. |
   <br>

3. `rate_limits` Arg

   To change the rate_limit and max_rate_limit for a specific route or endpoint use the rate_limits arg.
   The syntax is a bit different from the others, because two values are specified `{"route": (rate_limit, max_rate_limit), "endpoint": (rate_limit, max_rate_limit)}`. The variable rate_limit must be a number indicating how many requests per minute can come from a given ip. max_rate_limit indicates how many requests can come from all ips per minute, also a number.

   Example of a website that has a specific rate_limit on /api/:
   ```python
   ddosify = DDoSify(app, template_dirs={"/api/*": (60, 600)})
   ```
   <br>

4. `template_dirs` Arg

   To change the template directory of a particular route use the template_dirs arg.

   Example of a website that has a specific template directory on /api/:
   ```python
   ddosify = DDoSify(app, template_dirs={"/api/*": "/path/to/special/template/directory"})
   ```

   A template directory can look like this:
   ```
   template_directory\
              \captcha.html
              \block.html
              \rate_limited.html
              \change_language.html
   ```

   If one of the three templates does not exist in the folder, a 404 error is displayed when calling it. e.g. if you remove the changelanguage page at apis.
   <br>

5. `default_action` Arg

   To specify the default action of all routes or endpoints use the default_action arg.

   Example of a very paranoid website that has set its action to "fight" for all routes:
   ```python
   ddosify = DDoSify(app, default_action="fight")
   ```
   <br>

6. `default_hardness` Arg

   To specify the default hardness of all routes or endpoints use the default_hardness arg.

   Example of a very paranoid website that has set its hardness to 3 (= hard) for all routes:
   ```python
   ddosify = DDoSify(app, default_hardness=3)
   ```
   <br>

7. `default_rate_limit` Arg

   To specify the default requests of an IP per minute for all routes use the default_rate_limit variable. (Default: 120 = 2 requests per minute per IP)

   Example of a web page with custom rate_limit:
   ```python
   ddosify = DDoSify(app, default_rate_limit=60)
   ```
   <br>

8. `default_max_rate_limit` Arg

   To specify the default requests of all IPs per minute for all routes use the default_max_rate_limit variable. (Default: 1200 = 2 requests per minute from 10 IPs)

   Example of a web page with custom max_rate_limit:
   ```python
   ddosify = DDoSify(app, default_max_rate_limit=600)
   ```
   <br>

9. `default_template_dir` Arg

   To specify the default template_dir of all routes or endpoints use the default_template_dir arg.

   Example of a web page with custom template_dir:
   ```python
   ddosify = DDoSify(app, default_template_dir="/path/to/my/custom/template/directory")
   ```
   <br>

9. `verificationage` Arg

   Indicates the time in seconds how long a solved captcha is valid (Default: 3600 = 1 hour)

   Website with 3 hours verificationage:
   ```python
   ddosify = DDoSify(app, verificationage=10800)
   ```
   <br>

9. `withoutcookies` Arg

   If True, no cookies are created, and verification is proven via URL args (Default: False)

   Website with withoutcookies enabled:
   ```python
   ddosify = DDoSify(app, withoutcookies=True)
   ```
   <br>

9. `block_crawler` Arg

   If True, crawlers like Googlebot, further are estimated via their user agent as suspicious and not the website, good for websites that should not be crawled (Default: True)

   Web page with block_crawler enabled:
   ```python
   ddosify = DDoSify(app, block_crawler=True)
   ```
   <br>

9. `crawler_hints` Arg:

   If True, crawlers like Googlebot, are shown meta tags and the title of a normal web page, while they would have to solve a captcha. (Default: True)
   
   Web page with crawler_hints disabled:
   ```python
   ddosify = DDoSify(app, crawler_hints=False)
   ```
   <br>

[^1]: The block lists of [FireHol](https://firehol.org/), [Ipdeny](https://www.ipdeny.com), [Emerging Threats](https://rules.emergingthreats.net), [MyIp.ms](https://myip.ms/) and a list of [Tor exit nodes](https://www.torproject.org/) are used. These lists, the last excluded, only offer protection against data centres or known attackers.
[^2]: Text and, if the set strength is above 2, audio captchas can already be partially solved by robots, this is a solution for small websites or, e.g. dark web sites that cannot use third party solutions. However, it should still provide sufficient protection.
[^3]: For a captcha to work, however, the user's IP and user agent must normally be stored. The website may also collect data such as language to translate the website. Cookies can also be used, this is decided by the server administrator.
[^4]: Only if you have a large server that is supposed to protect a small server from DDoS attacks.
[^5]: Only if you do not use other services such as Google Analytics/Meta Pixel on your website.
