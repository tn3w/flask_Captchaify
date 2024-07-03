<h1 align="center">🤖 𝐟𝐥𝐚𝐬𝐤_𝐂𝐚𝐩𝐭𝐜𝐡𝐚𝐢𝐟𝐲</h1>
<p align="center">A strong Captcha and bot protection system for Flask with many features: rate limiting, special rules for users, web crawler detection, and automatic bot detection. Supports Google reCaptcha, hCaptcha, Cloudflare Turnstile, Friendly Captcha, and Altcha, as well as custom image, text, and audio captchas with your own data sets. Can also embed captchas in forms and offers its own Captcha box service called TrueClick.</p>
<p align="center"><a rel="noreferrer noopener" href="https://github.com/tn3w/flask_Captchaify"><img alt="Github" src="https://img.shields.io/badge/Github-141e24.svg?&style=for-the-badge&logo=github&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://pypi.org/project/flask-Captchaify/"><img alt="PyPI" src="https://img.shields.io/badge/PyPi-141e24.svg?&style=for-the-badge&logo=python&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://libraries.io/pypi/flask-Captchaify"><img alt="Libraries.io" src="https://img.shields.io/badge/Libraries.io-141e24.svg?&style=for-the-badge&logo=npm&logoColor=white"></a></p>

<br>

```python
from flask import Flask
from flask_Captchaify import Captchaify

app = Flask(__name__)
captchaify = Captchaify(app)

@app.route('/')
def index():
    """
    Extremely well protected route
    """

    return 'Hello human!🖐️'

if __name__ == '__main__':
    app.run(host = 'localhost', port = 9000)
```


### Table of Contents
   - [Table of Contents](#table-of-contents)
   - [How does it work](#how-does-it-work)
      - [Features](#features)
   - [About](#about)
      - [Installation](#installation)
      - [Some Screenshots](#some-screenshots)
      - [To-do's](#to-dos)
      - [Contributing](#note-for-contributors)
   - [Documentation](#documentation)
      - [Captcha Integration](#captcha-integration)
      - [Special Cases](#special-cases)
      - [Arguments](#arguments)


### How does it work?
In situations where it is deemed necessary, a captivating challenge may be presented to either the user or any automated agents, depending on the predetermined level of security required. Upon successful completion of this captivating challenge, a unique token is generated. This token serves as a secure vessel, encapsulating the client's information in an encrypted format. Subsequently, this token is deployed as both a cookie within the client's browser or as a parameter in the URL, denoted as 'captcha'. This mechanism ensures the continual validation of legitimacy with each subsequent request.


#### Features
- **Captcha Verification:** flask_Captchaify can verify captchas from third-party services like Google reCaptcha, hCaptcha, Cloudflare Turnstile, and Friendly Captcha, as well as custom verification options such as images, text or audio captchas.
- **Bot Identification:** flask_Captchaify can automatically identify and block known bots using block lists, API`s and similar mechanisms.
- **Rate Limiting:** flask_Captchaify allows you to set rate limits for requests to prevent bots from overwhelming your server.
- **Client-Specific Rules:** You can set rules specific to individual clients, such as allowing certain IP addresses to bypass the captcha.
- **JavaScript not required:** flask_Captchaify does not require JavaScript. All captchas are fully functional without it. (Third party services like Google reCaptcha, hCaptcha, Cloudflare Turnstile, Friendly Captcha, Altcha and Trueclick require JavaScript to work.)
- **Crawler Detection:** flask_Captchaify can detect and block web crawlers from accessing your site. Web Crawlers can also be given hints and be shown meta tags.
- **Customizable Dataset:** You can customize the captchas by providing your own dataset of images and keywords.
- **Customizable Templates:** You can customize the templates used for the captchas and error pages.
- **Customizable Themes:** Users can customize the themes used for the captchas and error pages.
- **Multiple Captcha Types:** flask_Captchaify supports multiple types of captchas, including one-click captchas, custom captchas, and captchas from third-party services.
- **Personalization:** You can customize the behavior of flask_Captchaify by providing your own arguments and values.
- **Error Handling:** flask_Captchaify handles errors and displays custom error pages.
- **Fully Open Source:** flask_Captchaify is fully open source and free to use. ʕっ•ᴥ•ʔっ

<br>

## About

### Installation
1. Make sure you have the latest version of Python and Pip installed, you also need git installed.
2. Install the script with pip `pip install flask_Captchaify` or manually via `git clone https://github.com/tn3w/flask_Captchaify` or download the zip.
3. If you installed it manually, make sure your python script is in the folder where there is a subfolder flask_Captchaify, and make sure you run `pip install -r requirements.txt` in the flask_Captchaify folder.
4. Make sure that after:
   ```python
   app = Flask(__name__)
   ```
   You add the line:
   ```python
   captchaify = Captchaify(app, action = "fight")
   ```
   And at the beginning of the file add the import:
   ```python
   from flask_Captchaify import Captchaify
   ```

### Some Screenshots
- Captcha oneclick: [Display](https://github.com/tn3w/flask_Captchaify/releases/download/img2_v1.7/oneclick_captcha.png)
- Captcha multiclick: [Display](https://github.com/tn3w/flask_Captchaify/releases/download/img2_v1.7/multiclick_captcha.png)
- Captcha using Google reCaptcha: [Display](https://github.com/tn3w/flask_Captchaify/releases/download/img2_v1.7/google_captcha.png)
- Site to change language: [Display](https://github.com/tn3w/flask_Captchaify/releases/download/img2_v1.7/change_language.png)
- Site when user is blocked: [Display](https://github.com/tn3w/flask_Captchaify/releases/download/img2_v1.7/blocked.png)
- Site when user is rate limited: [Display](https://github.com/tn3w/flask_Captchaify/releases/download/img2_v1.7/rate_limited.png)
- Site when user has javascript disabled and a captcha third party like Google reCaptcha is used: [Display](https://github.com/tn3w/flask_Captchaify/releases/download/img2_v1.7/nojs.png)


### To-Do's
- [x] Integrate Captchaify Trueclick as captcha type
- [x] Add location propertys
- [x] Add is_captcha_valid and show_captcha function to add an way to check in an specific case in an route
- [ ] Add clickable Captcha
- [ ] Captcha data set with emojis


### Note for Contributors
If you want to contribute, please read [CONTRIBUTING.md](https://github.com/tn3w/flask_Captchaify/blob/master/CONTRIBUTING.md)

<br>

# Documentation

## Captcha Integration

Google reCaptcha, hCaptcha, Cloudflare Turnstile and Altcha are automatically integrated into captchas if the site_key and secret are given. (site_key and secret are not required for Altcha). Recommendation: Use Altcha, you don't need authorization tokens and the challenges are generated by the server. Altcha uses a Prove of Work system that is future-proof.

Here are all the available captcha third parties:
| Third party          | Description                                                                                                                       | Verify Function      |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| Google reCaptcha     | Uses Google reCaptcha for verification. Set `recaptcha_site_key` and `recaptcha_secret`.                                          | is_recaptcha_valid() |
| hCaptcha             | Uses hCaptcha for verification. Set `hcaptcha_site_key` and `hcaptcha_secret`.                                                    | is_hcaptcha_valid()  |
| Cloudflare Turnstile | Uses Cloudflare Turnstile for verification. Set `turnstile_site_key` and `turnstile_secret`.                                      | is_turnstile_valid() |
| Friendly Captcha     | Uses Friendly Captcha for verification. Set `friendly_site_key` and `friendly_secret`.                                            | is_friendly_valid()  |
| Altcha               | Use a Prove-of-Work from Altcha to make spam more difficult. (Recommended if you do not want to use our own tools.)               | is_altcha_valid()    |
| Trueclick            | Uses Trueclick for verification. See [https://github.com/tn3w/TrueClick](https://github.com/tn3w/TrueClick) for more information. | is_trueclick_valid() |


Template example:
```html
<!DOCTYPE html>
<html>
   <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Altcha Example</title>
   </head>
   <body>
      <form method="POST">
         <input name="name" type="text">
         <input name="password" type="password">
         {{ altcha }}
         <button type="submit">Submit</button>
      </form>
   </body>
</html>
```

Use the Flask functions render_template or render_template_string to render the template, if you do not render the template the captcha will not be added.

An example that renders the template and checks the captcha:
```python
from flask import Flask, render_template
from flask_Captchaify import Captchaify

app = Flask(__name__)
captchaify = Captchaify(app)

@app.route('/', methods=['GET', 'POST'])
def index():
   """
   Index page
   """

   if request.method == 'POST':
      if not captchaify.is_altcha_valid():
         return 'Captcha incorrect.'

      return 'Correct.'

   return render_template('example.html')

if __name__ == '__main__':
   app.run()
```

<br>

## Special Cases

In some cases or if you like it better, you can use a combination of `captchaify.is_captcha_valid()` and `captchaify.show_captcha()` to show a captcha when needed.

An example route that displays a captcha to all clients using proxies:
```python
from flask import Flask
from flask_Captchaify import Captchaify

app = Flask(__name__)
captchaify = Captchaify(app, action = 'allow') # Captchaify is detecting proxies automatically, here this is disabled

# Or use:
# captchaify = Captchaify(app, rules = [{'rule': ['path', 'is', '/login'], 'change': {'action': 'allow'}}])

@app.route('/login') # you can also use an endpoint
def login():
   if not captchaify.is_captcha_valid() and\
      (not captchaify.is_valid_ip or captchaify.is_proxy\
       or captchaify.is_spammer or captchaify.is_tor): # Crawler: `or captchaify.is_crawler`
      return captchaify.show_captcha()

   return 'MY LOGIN TEMPLATE' # the user is not a robot.

if __name__ == '__main__':
   app.run()
```

<br>

## Arguments
All args and default value:
```python
args = {
   "app": None, "rules": [],
   "action": 'auto', "captcha_type": 'oneclick',
   "dataset": 'keys', "dataset_size": (20, 100),
   "dataset_dir": DATASETS_DIR, "hardness": 1,
   "verification_age": 3600, "template_dir": TEMPLATE_DIR,
   "without_customisation": False, "without_cookies": False,
   "without_arg_transfer": False, "without_watermark": False,
   "third_parties": ['geoip', 'tor', 'ipapi', 'stopforumspam'],
   "enable_rate_limit": True, "rate_limit": (15, 300),
   "block_crawler": True, "crawler_hints": True,"as_route": False,
   "fixed_route_name": '_captchaify', "theme": 'light', "language": 'en',
   "without_trueclick": False, "error_codes": [],
   "recaptcha_site_key": None, "recaptcha_secret": None,
   "hcaptcha_site_key": None, "hcaptcha_secret": None,
   "turnstile_site_key": None, "turnstile_secret": None,
   "friendly_site_key": None, "friendly_secret": None
}
```

<br>

1. ***`app` Arg***

   A Flask() object of a Flask app that is modified by Captchaify so that each request is checked for bots

   Example:
   ```python
   from flask import Flask
   from flask_Captchaify import Captchaify

   app = Flask('MyWebsite')
   captchaify = Captchaify(app)
   ```

<br>

2. ***`rules` Arg***

   Certain changes based on specific criteria such as IP, proxy, hosting or geo information

   Web page that blocks the localhost Ip:
   ```python
   captchaify = Captchaify(app, rules=[{"rule": ['ip', 'equals', '127.0.0.1'], "change": {"action": "block"}}])
   ```

   Criteria can also be combined, with 'and' meaning that both criteria must be met and 'or' meaning that one of the two criteria must be met:
   ```python
   rules = [{"rule": ['ip', 'is in', ['127.0.0.1', '10.0.0.1'], 'or', 'proxy', 'is', True]}, "change": {"action": "block"}]
   ```

   <br>

   **Client Info**

   The following client info fields can be compared:
   | Name of field  | Type | Information                                                   | Example                                                                          |
   | -------------- | ---- | ------------------------------------------------------------- | -------------------------------------------------------------------------------- |
   | ip             | str  | Client's IP address.                                          | 169.150.196.74                                                                   |
   | user_agent     | str  | User agent string of the client's browser.                    | Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0 |
   | invalid_ip     | bool | Boolean indicating if the IP is invalid.                      | False                                                                            |
   | continent      | str  | Name of the continent.                                        | Europe                                                                           |
   | continent_code | str  | Continent code. (ISO 3166)                                    | EU                                                                               |
   | country        | str  | Name of the country.                                          | The Netherlands                                                                  |
   | country_code   | str  | Country code. (ISO 3166)                                      | NL                                                                               |
   | region         | str  | Name of the region.                                           | North Holland                                                                    |
   | region_code    | str  | Region code. (ISO 3166)                                       | NH                                                                               |
   | city           | str  | Name of the city.                                             | Amsterdam                                                                        |
   | district       | str  | Name of the district.                                         | None                                                                             |
   | zip            | int  | Postal code.                                                  | 1012                                                                             |
   | lat            | int  | Latitude.                                                     | 52.3759                                                                          |
   | lon            | int  | Longitude.                                                    | 4.8975                                                                           |
   | timezone       | str  | Timezone.                                                     | Europe/Amsterdam                                                                 |
   | offset         | int  | Timezone offset.                                              | 7200                                                                             |
   | currency       | str  | Local currency. (ISO 4217)                                    | EUR                                                                              |
   | isp            | str  | Internet Service Provider.                                    | Datacamp Limited                                                                 |
   | org            | str  | Organization name.                                            | CSNext                                                                           |
   | as             | str  | Autonomous system name.                                       | Datacamp Limited                                                                 |
   | as_code        | int  | Autonomous system code.                                       | 212238                                                                           |
   | reverse        | str  | Reverse DNS lookup result.                                    | unn-169-150-196-74.datapacket.com                                                |
   | mobile         | bool | Boolean indicating if the connection is via a mobile network. | False                                                                            |
   | proxy          | bool | Boolean indicating if the client is using a proxy.            | True                                                                             |
   | tor            | bool | Boolean indicating if the client is using Tor.                | False                                                                            |
   | hosting        | bool | Boolean indicating if the client is using a hosting service.  | True                                                                             |
   | forum_spammer  | bool | Boolean indicating if the client is a known forum spammer.    | True                                                                             |
   | netloc         | str  | Network location part of the URL. (includes Port)             | domain.example.com:80                                                            |
   | hostname       | str  | Fully qualified domain name (FQDN) of the server.             | domain.example.com                                                               |
   | domain         | str  | Primary domain name, which is a subset of the hostname.       | example.com                                                                      |
   | path           | str  | Path component of the URL, indicates a specific resource.     | /login                                                                           |
   | endpoint       | str  | The `request.endpoint` Endpoint Information.                  | login                                                                            |
   | scheme         | str  | Protocol used to access the resource.                         | https                                                                            |
   | url            | str  | Complete URL that combines all the individual components.     | https://domain.example.com/login                                                 |

   <br>

   The following operators are available:
   | Name of Operator                                                   | The same as             |
   | ------------------------------------------------------------------ | ----------------------- |
   | ==, equals, equal, is                                              | field == value          |
   | !=, does not equal, does not equals, not equals, not equal, not is | field != value          |
   | contains, contain                                                  | value in field          |
   | does not contain, does not contains, not contain, not contains     | value not in field      |
   | is in, in                                                          | field in value          |
   | is not in, not is in, not in                                       | field not in value      |
   | greater than, larger than                                          | field > value           |
   | less than                                                          | field < value           |
   | starts with, begins with                                           | field.startswith(value) |
   | ends with, concludes with, finishes with                           | field.endswith(value)   |

   Where field is the type of data e.g. `ip` and value is the value it should have e.g. `169.150.196.74`.

   <br>

   All changes that can be made by these rules:
   | Name of the change | Type            | Example                                                     |
   | ------------------ | --------------- | ----------------------------------------------------------- |
   | captcha_type       | str             | multiclick                                                  |
   | dataset            | str             | ai-dogs                                                     |
   | dataset_dir        | str             | /path/to/dataset/dir                                        |
   | action             | str             | allow                                                       |
   | hardness           | int (1-5)       | 3                                                           |
   | enable_rate_limit  | bool            | True                                                        |
   | rate_limit         | Tuple[int, int] | (20, 100)                                                   |
   | template_dir       | str             | /path/to/template/dir                                       |
   | recaptcha_site_key | str             | 6Lfp1PEpAAAAANS3PIXmQ4c7k2p7gqxMopD5Npy3                    |
   | recaptcha_secret   | str             | 6Lfp1OEyBBBBBDjuZ-xK8H2LMnPVFQR-5nKkTBY9                    |
   | hcaptcha_site_key  | str             | d4f8bc19-c517-4387-9cb1-826935d73f47                        |
   | hcaptcha_secret    | str             | ES_e7d43d0818455496a48d22ddc3367d68                         |
   | turnstile_site_key | str             | 0x5CCCCCCAp-qCgUJkS4MJa                                     |
   | turnstile_secret   | str             | 0x5BBBBBBBc-vRpT3xZNR1bKfDJKUPGLQPF                         |
   | friendly_site_key  | str             | WZMSUDMH2PXWVJN9                                            |
   | friendly_secret    | str             | B2YL26SFRPF3C9VOMOOF9HW8R0MX5WESVXO3OZ5TJ2AP62L91B4PCUP5C1J |

   <br>

   **Asterik `*`**

   The asterisk creates the customization options for information comparisons. The asterisk (*) serves as a wildcard, representing any number of characters including zero.

   Example of a rule that all routes that start with /login then have a string and then have /development as route e.g. `/login/api/development` or `/login/2fa/development`:
   ```python
   rules = [{"rule": ['path', 'is', '/login*/development']}, "change": {"action": "block"}]
   ```

   <br>

   Here are all the things that can be changed:

   **Captcha types (`captcha_type`)**

   | Name of captcha type | Displayed Captchas                                                                                                  |
   | --------------       | ------------------------------------------------------------------------------------------------------------------- |
   | oneclick (Default)   | The user only needs one click to confirm that he is not a bot                                                       |
   | multiclick           | The user must select several images that match a motif (harder)                                                     |
   | text                 | The user enters a text combination from an image into an input                                                      |
   | audio                | The user enters a text combination from an audio into an input                                                      |
   | text&audio           | The user enters a text and an audio combination into an input                                                       |
   | altcha               | Use a Prove-of-Work from Altcha to make spam more difficult. (Recommended if you do not want to use our own tools.) |
   | trueclick            | TrueClick is an in-house programmed clickable third party captcha. It is built in.                                  |
   | recaptcha            | Uses Google Recaptcha for verification. Set `recaptcha_site_key` and `recaptcha_secret`.                            |
   | hcaptcha             | Uses HCaptcha for verification. Set `hcaptcha_site_key` and `hcaptcha_secret`.                                      |
   | turnstile            | Uses Cloudflare Turnstile for verification. Set `turnstile_site_key` and `turnstile_secret`.                        |
   | friendly             | Uses Friendly Captcha for verification. Set `friendly_site_key` and `friendly_secret`.                              |

   Example of a website that has set its captcha type to "multiclick" for specific ips:
   ```python
   rules = [{"rule": ['ip', 'is in', ('1.1.1.1', '1.0.0.1', '8.8.8.8')]}, "change": {"captcha_type": "multiclick"}]
   ```

   <br>

   **Datasets (`dataset`)**

   | Name of dataset | Displayed Captchas                                                                                 |
   | --------------- | -------------------------------------------------------------------------------------------------- |
   | keys            | Displays images based on specific keywords of landscapes, objects, and more (default for oneclick) |
   | animals         | Displays 50 different animal species (default for multiclick)                                      |
   | ai-dogs         | Displays smiling and not smiling dogs                                                              |

   Example of a website that has set its data set to "keys" for specific ips:
   ```python
   rules = [{"rule": ['ip', 'is in', ('1.1.1.1', '1.0.0.1', '8.8.8.8')]}, "change": {"dataset": "ai-dogs"}]
   ```

   <br>

   **Dataset Dir (`dataset_dir`)**

   ```
   dataset_dir\
          \keys.json
          \animals.json
          \ai-dogs.json
          ...
   ```

   Example of a website that specifies its own dataset folder for specific ips:
   ```python
   rules = [{"rule": ['ip', 'is in', ('1.1.1.1', '1.0.0.1', '8.8.8.8')]}, "change": {"dataset_dir": "/path/to/dataset/dir"}]
   ```

   <br>

   **Actions (`action`)**

   | Name of action | Executing Action                                                     |
   | -------------- | -------------------------------------------------------------------- |
   | allow          | Allows all traffic through, regardless of whether the IP is blocked. |
   | block          | Blocks all traffic if it is blocked, without captcha.                |
   | fight          | Displays a captcha to all traffic, whether suspicious or not.        |
   | auto           | Default value, shows only suspicious traffic captchas.               |

   Example of a website that has set its action to "block" for specific ips:
   ```python
   rules = [{"rule": ['ip', 'is in', ('1.1.1.1', '1.0.0.1', '8.8.8.8')]}, "change": {"action": "block"}]
   ```

   <br>

   **Hardness (`hardness`)**

   The variable hardness must be a number between 1 and 5. The higher the value, the harder the captcha is. (Default: 1)

   Example of a website that has set its hardness to 3 for specific ips:
   ```python
   rules = [{"rule": ['ip', 'is in', ('1.1.1.1', '1.0.0.1', '8.8.8.8')]}, "change": {"hardness": 3}]
   ```

   <br>

   **Enable Rate Limit (`enable_rate_limit`)**
   
   To enable or disable rate limits.

   Example of a website that has set its rate limit to false for specific ips:
   ```python
   rules = [{"rule": ['ip', 'is in', ('1.1.1.1', '1.0.0.1', '8.8.8.8')]}, "change": {"enable_rate_limit": False}]
   ```

   <br>

   **Rate Limits (`rate_limit`)**

   The syntax is a bit different from the others, because two values are specified `(rate_limit, max_rate_limit)`. The variable rate_limit must be a number indicating how many requests per minute can come from a given ip. max_rate_limit indicates how many requests can come from all ips per minute, also a number.

   Example of a website that has set its rate limit to (20, 1200) for specific ips:
   ```python
   rules = [{"rule": ['ip', 'is in', ('1.1.1.1', '1.0.0.1', '8.8.8.8')]}, "change": {"rate_limit": (20, 1200)}]
   ```

   <br>

   **Template Dir (`template_dir`)**

   To change the template directory of a particular route use the template_dirs arg.

   A template directory can look like this:
   ```
   template_directory\
              \captcha_text_audio.html
              \captcha_oneclick.html
              \captcha_multiclick.html
              \captcha_third_party.html
              \change_language.html
              \blocked.html
              \rate_limited.html
              \nojs.html
              \exception.html
   ```

   If one of the three templates does not exist in the folder, a 404 error is displayed when calling it. e.g. if you remove the change_language page at apis.

   Example of a website that has set its template dir to "template_directory" for specific ips:
   ```python
   rules = [{"rule": ['ip', 'is in', ('1.1.1.1', '1.0.0.1', '8.8.8.8')]}, "change": {"template_dir": "/path/to/template/dir"}]
   ```

   <br>

   **Site Keys and Secrets**

   To change the site_key and secret of a particular route use the recaptcha_site_key, recaptcha_secret, hcaptcha_site_key, hcaptcha_secret, turnstile_site_key, turnstile_secret, friendly_site_key and friendly_secret args.

   For google reCaptcha you can get this here: https://www.google.com/recaptcha/admin/create, for hCaptcha here: https://dashboard.hcaptcha.com/login, for Cloudflare Turnstile here: https://dash.cloudflare.com/sign-up?to=/:account/turnstile (Important: You must have an domain with Cloudflare) and for Friendly Captcha here: [https://friendlycaptcha.com/signup/](https://friendlycaptcha.com/signup/), after signing up you can create an organization and get your site key under `Applications` and secret under `Api Keys`.

   Usually site_key and secret are displayed after creating an account or when linking a domain or ip.

   Example of a website that has set its recaptcha_site_key to "recaptcha_site_key" for specific ips:
   ```python
   rules = [{"rule": ['ip', 'is in', ('1.1.1.1', '1.0.0.1', '8.8.8.8')]}, "change": {"recaptcha_site_key": "recaptcha_site_key"}]
   ```

<br>

3. ***`action` Arg***

   To specify the default action of all routes or endpoints use the action arg.

   Example of a very paranoid website that has set its action to "fight" for all routes:
   ```python
   captchaify = Captchaify(app, action="fight")
   ```

   All actions:

   | Name of action | Executing Action                                                     |
   | -------------- | -------------------------------------------------------------------- |
   | allow          | Allows all traffic through, regardless of whether the IP is blocked. |
   | block          | Blocks all traffic if it is blocked, without captcha.                |
   | fight          | Displays a captcha to all traffic, whether suspicious or not.        |
   | auto           | Default value, shows only suspicious traffic captchas.               |

<br>

4. ***`captcha_type` Arg***

   To specify the default captcha type of all routes or endpoints use the captcha_type arg.

   Example of a website that has set its types to "text" (for text bases captchas) for all routes:
   ```python
   captchaify = Captchaify(app, captcha_type="text")
   ```

   All captcha types:

   | Name of captcha type | Displayed Captchas                                                                                                  |
   | --------------       | ------------------------------------------------------------------------------------------------------------------- |
   | oneclick (Default)   | The user only needs one click to confirm that he is not a bot                                                       |
   | multiclick           | The user must select several images that match a motif (harder)                                                     |
   | text                 | The user enters a text combination from an image into an input                                                      |
   | audio                | The user enters a text combination from an audio into an input                                                      |
   | text&audio           | The user enters a text and an audio combination into an input                                                       |
   | altcha               | Use a Prove-of-Work from Altcha to make spam more difficult. (Recommended if you do not want to use our own tools.) |
   | trueclick            | TrueClick is an in-house programmed clickable third party captcha. It is built in.                                  |
   | recaptcha            | Uses Google Recaptcha for verification. Set `recaptcha_site_key` and `recaptcha_secret`.                            |
   | hcaptcha             | Uses HCaptcha for verification. Set `hcaptcha_site_key` and `hcaptcha_secret`.                                      |
   | turnstile            | Uses Cloudflare Turnstile for verification. Set `turnstile_site_key` and `turnstile_secret`.                        |
   | friendly             | Uses Friendly Captcha for verification. Set `friendly_site_key` and `friendly_secret`.                              |

<br>

5. ***`dataset` Arg***	

   To specify the default data set of all routes or endpoints use the dataset arg.

   Example of a website that has set its data set to "keys" for all routes:
   ```python
   captchaify = Captchaify(app, dataset="keys")
   ```

   All data sets:

   | Name of dataset | Displayed Captchas                                                                                 |
   | --------------- | -------------------------------------------------------------------------------------------------- |
   | keys            | Displays images based on specific keywords of landscapes, objects, and more (default for oneclick) |
   | animals         | Displays 50 different animal species (default for multiclick)                                      |
   | ai-dogs         | Displays smiling and not smiling dogs                                                              |

   (more is in progress ʕっ•ᴥ•ʔっ)

<br>

6. ***`dataset_size` Arg***

   The size of the data set with e.g. images and keywords that determine how much of a data set is used, if a lot is used this can reduce RAM capacity but also increase security.
   Either a tuple of 2 numbers where the first indicates how many images per keyword (always the first ones) can be used (recommended around 20, maximum 200 or more depending on the data set) and the second number how many keywords are e.g. (images_per_keyword, number_of_keywords), default setting: (20, 100).

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

   The more images per keyword, the more inaccurate the user rate becomes, as images further behind in the image search and in the data set could no longer show the keyword.
   It is recommended that you generate your own dataset as the default data could be trained, use the script written in [https://github.com/tn3w/Captcha_Datasets](https://github.com/tn3w/Captcha_Datasets) and put the file in a folder and use the `dataset_dir` Arg to use it.

   Example of a website that uses 100 images per keyword and 140 keywords:
   ```python
   captchaify = Captchaify(app, dataset_size=(100, 140))
   ```

<br>

7. ***`dataset_dir` Arg***

   Specifies where the program can find data sets. A dataset should be a json file.

   Example of a website that specifies its own dataset folder:
   ```python
   captchaify = Captchaify(app, dataset_dir='/path/to/my/dataset')
   ```

   A dataset dir can look like this:
   ```
   dataset_dir\
          \keys.json
          \animals.json
          \ai-dogs.json
          ...
   ```

<br>

8. ***`hardness` Arg***

   Specifies the default hardness of the captcha.
   The variable hardness must be a number between 1 and 5. The higher the value, the harder the captcha is. (Default: 1)

   Example of a website that has set its default hardness to 3:
   ```python
   captchaify = Captchaify(app, hardness=3)
   ```

<br>

9. ***`verification_age` Arg***

   Indicates the time in seconds how long a solved captcha is valid (Default: 3600 = 1 hour)

   Website with 3 hours verification_age:
   ```python
   captchaify = Captchaify(app, verification_age=10800)
   ```

<br>

9. ***`template_dir` Arg***

   To specify the default template_dir of all routes or endpoints use the template_dir arg.

   Example of a web page with custom template_dir:
   ```python
   captchaify = Captchaify(app, template_dir="/path/to/my/custom/template/directory")
   ```

   A template directory can look like this:
   ```
   template_directory\
              \captcha_text_audio.html
              \captcha_oneclick.html
              \captcha_multiclick.html
              \captcha_third_party.html
              \change_language.html
              \blocked.html
              \rate_limited.html
              \nojs.html
              \exception.html
              ...
   ```

<br>

9. ***`without_customisation` Arg***

   Whether to allow customisation of the captcha site (theme and language) or not.
   If you want the best possible user experience, allow customization, if you just want protection, activate this option

   Web page where customisation is not allowed:
   ```python
   captchaify = Captchaify(app, without_customisation = True)
   ```

<br>

9. ***`without_cookies` Arg***

   If True, no cookies are created, and verification is proven via URL args. (Default: False)

   Website with without_cookies enabled:
   ```python
   captchaify = Captchaify(app, without_cookies=True)
   ```

<br>

9. ***`without_arg_transfer` Arg***

   Whether to allow other args to be passed to sites after the captcha has been solved. (Default: False)

   Web page where this is activated:
   ```python
   captchaify = Captchaify(app, without_other_args = True)
   ```

<br>

9. ***`without_watermark` Arg***

   Whether to show the Captchaify watermark or not. (Default: False)
   You don't have to use the Captchaify watermark, if you like the project you can give it a star on GitHub.

   When you use custom templates you can remove the watermark in the template.

   Web page where this is activated and the watermark is not shown:
   ```python
   captchaify = Captchaify(app, without_watermark = True)
   ```

<br>

9. ***`third_parties` Arg***

   Specifies which third parties are used to check the IP addresses. By default, all 4 third parties are used. (See list)

   Web page that only asks a third party for Tor Ip addresse information:
   ```python
   captchaify = Captchaify(app, third_parties=["tor"])
   ```

   Possible entries would be:
   | Abbreviation         | Who is requested and how does the evaluation mechanism work?                                                                           |
   | -------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
   | tor                  | Uses dnspython to check if an IP is a Tor Exit Node. See [Stackoverflow #78535126](https://stackoverflow.com/questions/78535126/is-there-a-way-to-find-out-if-a-particular-ip-is-coming-from-tor-or-acting-as-a) |
   | reverse              | `socket.gethostbyaddr(client_ip)` is used to get the reverse DNS name of the IP address.                                               |
   | ipapi                | [Ipapi](https://ipapi.com) is requested with the Ip and the result of the fields "proxy" and "hosting" is used                         |
   | stopforumspam        | [StopForumSpam](https://stopforumspam.com) is requested and the result is used                                                         |

<br>

9. ***`as_route` Arg***

   Specifies whether Captchaify pages are displayed as separate routes in order not to confuse the cache between normal pages and Captchaify pages (e.g. for Cloudflare)

   Web page where this is activated:
   ```python
   captchaify = Captchaify(app, as_route = True)
   ```

<br>

9. ***`fixed_route_name` Arg***

   Specifies the name of the route that is used if Captchaify pages are displayed as separate routes. (Default: `_captchaify`)

   Web page where this is edited:
   ```python
   captchaify = Captchaify(app, fixed_route_name = "") # Can be any string and nothing
   ```

<br>

9. ***`enable_rate_limit` Arg***

   Whether to enable rate limiting or not.

   Example of a web page with rate limiting enabled:
   ```python
   captchaify = Captchaify(app, enable_rate_limit=True)
   ```

<br>

9. ***`rate_limit` Arg***

   To specify the default rate_limit of all routes or endpoints use the rate_limit arg.
   It is a tuple of 2 values: (rate_limit, max_rate_limit)

   `rate_limit` is a number indicating how many requests per 10 seconds can come from a given ip.
   `max_rate_limit` indicates how many requests can come from all ips 10 seconds, also a number.

   Example of a web page with custom rate_limit:
   ```python
   captchaify = Captchaify(app, rate_limit=60)
   ```

<br>

9. ***`block_crawler` Arg***

   If True, crawlers like Googlebot, further are estimated via their user agent as suspicious and not the website, good for websites that should not be crawled (Default: True)

   Web page with block_crawler enabled:
   ```python
   captchaify = Captchaify(app, block_crawler=True)
   ```

<br>

9. ***`crawler_hints` Arg***

   If True, crawlers like Googlebot, are shown meta tags and the title of a normal web page, while they would have to solve a captcha. (Default: True)
   
   Web page with crawler_hints disabled:
   ```python
   captchaify = Captchaify(app, crawler_hints=False)
   ```

<br>

9. ***`theme` Arg***

   To specify the default theme of all routes or endpoints use the theme arg.

   Example of a website that has set its theme to "dark" for all routes:
   ```python
   captchaify = Captchaify(app, theme="dark")
   ```

   All themes:

   | Name of theme | Description                                                                           |
   | ------------- | ------------------------------------------------------------------------------------- |
   | light         | Bright theme with a light background and dark text, ideal for well-lit settings.      |
   | dark          | Dark theme with a dark background and light text, perfect for low-light environments. |

<br>

9. ***`language` Arg***

   To specify the default language of all routes or endpoints use the language arg.

   Example of a website that has set its language to "de" (German language) for all routes:
   ```python
   captchaify = Captchaify(app, language="de")
   ```

   A list off all languages according to ISO 639-1:
   ```python
   languages = ['en', 'es', 'zh-cn', 'hi', 'ar', 'fr', 'ru', 'pt', 'de', 'ja', 'bn', 'pa', 'ko', 'it', 'vi', 'zh-tw', 'te', 'mr', 'ta', 'ur', 'tr', 'th', 'gu', 'fa', 'pl', 'uk', 'ro', 'nl', 'hu', 'el', 'cs', 'sv', 'he', 'da', 'fi', 'no', 'sk', 'hr', 'ms', 'id', 'sr', 'lt', 'sl', 'et', 'lv', 'sw', 'bg', 'ka', 'az', 'kk', 'uz', 'hy', 'sq', 'my', 'km', 'mk', 'am', 'ne', 'lo', 'si', 'sd', 'ug', 'mn', 'ky', 'ps', 'ku', 'gl', 'mt', 'so', 'gd', 'cy', 'lb', 'yi', 'ha', 'haw', 'mg', 'yo', 'ny', 'ceb', 'co', 'fy', 'ig', 'is', 'jw', 'la', 'mi', 'su', 'tg', 'tl', 'xh', 'zu', 'af', 'eu', 'be', 'bs', 'ca', 'eo', 'ht', 'iw', 'hmn', 'ga', 'kn', 'ml', 'or', 'sm', 'st', 'sn']
   ```

<br>

9. ***`without_trueclick` Arg***

   Whether to add an TrueClick route. If you do not use TrueClick at all, activate this option. It removes all routes that are not required for TrueClick. (Default: False)

   Web page with without_trueclick enabled:
   ```python
   captchaify = Captchaify(app, without_trueclick=True)
   ```

<br>

9. ***`error_codes` Arg***

   Which HTTP status codes or Exception classes should be handled by Captchaify. By default, none HTTP status codes are handled. (See list)

   You can customize the error data in the following way:
   ```python
   error_codes = [404] # Normal HTTP error message, title and error code
   error_codes = [
      404,
      {
         "code": 500, "code_override": "Oops",
         "title": "Internal Server Error",
         "description": "Something went wrong"
      }
   ] # 404 is normal but 500 is handled with custom data
   ```

   Web page where only the status code `418 I'm a teapot` is handled:
   ```python
   captchaify = Captchaify(app, error_codes = [418])
   ```

   A list off all HTTP status codes and their descriptions can be found here: [https://en.wikipedia.org/wiki/List_of_HTTP_status_codes](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes).
   ```python
   error_codes = [400, 401, 403, 404, 405, 406, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 422, 423, 424, 428, 429, 431, 451, 500, 501, 502, 503, 504, 505]
   ```

<br>

9. ***`recaptcha_site_key` Arg***

   Is required if Google reCaptcha is used as captcha_type or in an form.
   For Google reCaptcha you can get this here: [https://www.google.com/recaptcha/admin/create](https://www.google.com/recaptcha/admin/create)
   Usually site_key and secret are displayed after creating an account or when linking a domain or ip.

   Example: `6Lfp1PEpAAAAANS3PIXmQ4c7k2p7gqxMopD5Npy3`

   Web page where this is set:
   ```python
   captchaify = Captchaify(app, recaptcha_site_key = '<site-key>')
   ```

<br>

9. ***`recaptcha_secret` Arg***

   Is required if Google reCaptcha is used as captcha_type or in an form.
   For Google reCaptcha you can get this here: [https://www.google.com/recaptcha/admin/create](https://www.google.com/recaptcha/admin/create)
   Usually site_key and secret are displayed after creating an account or when linking a domain or ip.

   Example: `6Lfp1OEyBBBBBDjuZ-xK8H2LMnPVFQR-5nKkTBY9`

   Web page where this is set:
   ```python
   captchaify = Captchaify(app, recaptcha_secret = '<secret>')
   ```

<br>

9. ***`hcaptcha_site_key` Arg***

   Is required if hCaptcha is used as captcha_type or in an form.
   For hCaptcha you can get this here: [https://dashboard.hcaptcha.com/login](https://dashboard.hcaptcha.com/login)
   Usually site_key and secret are displayed after creating an account or when linking a domain or ip.

   Example: `d4f8bc19-c517-4387-9cb1-826935d73f47`

   Web page where this is set:
   ```python
   captchaify = Captchaify(app, hcaptcha_site_key = '<site-key>')
   ```

<br>

9. ***`hcaptcha_secret` Arg***

   Is required if hCaptcha is used as captcha_type or in an form.
   For hCaptcha you can get this here: [https://dashboard.hcaptcha.com/login](https://dashboard.hcaptcha.com/login)
   Usually site_key and secret are displayed after creating an account or when linking a domain or ip.

   Example: `ES_e7d43d0818455496a48d22ddc3367d68`

   Web page where this is set:
   ```python
   captchaify = Captchaify(app, hcaptcha_secret = '<secret>')
   ```

<br>

9. ***`turnstile_site_key` Arg***

   Is required if Cloudflare Turnstile is used as captcha_type or in an form.
   For Cloudflare Turnstile you can get this here: [https://dash.cloudflare.com/sign-up?to=/:account/turnstile](https://dash.cloudflare.com/sign-up?to=/:account/turnstile)
   Important: Here you need a domain.
   Usually site_key and secret are displayed after creating an account or when linking a domain or ip.

   Example: `0x5CCCCCCAp-qCgUJkS4MJa`

   Web page where this is set:
   ```python
   captchaify = Captchaify(app, turnstile_site_key = '<site-key>')
   ```

<br>

9. ***`turnstile_secret` Arg***

   Is required if Cloudflare Turnstile is used as captcha_type or in an form.
   For Cloudflare Turnstile you can get this here: [https://dash.cloudflare.com/sign-up?to=/:account/turnstile](https://dash.cloudflare.com/sign-up?to=/:account/turnstile)
   Important: Here you need a domain.
   Usually site_key and secret are displayed after creating an account or when linking a domain or ip.

   Example: `0x5BBBBBBBc-vRpT3xZNR1bKfDJKUPGLQPF`

   Web page where this is set:
   ```python
   captchaify = Captchaify(app, turnstile_secret = '<secret>')
   ```

<br>

9. ***`friendly_site_key` Arg***

   Is required if Friendly Captcha is used as captcha_type or in an form.
   For Friendly Captcha you can get this here: [https://friendlycaptcha.com/signup/](https://friendlycaptcha.com/signup/), after signing up you can create an organization and get your site_key under `Applications`.

   Example: `WZMSUDMH2PXWVJN9`

   Web page where this is set:
   ```python
   captchaify = Captchaify(app, friendly_site_key = '<site-key>')
   ```

<br>

9. ***`friendly_secret` Arg***

   Is required if Friendly Captcha is used as captcha_type or in an form.
   For Friendly Captcha you can get this here: [https://friendlycaptcha.com/signup/](https://friendlycaptcha.com/signup/), after signing up you can create an organization and get your secret under `Api Keys`.

   Example: `B2YL26SFRPF3C9VOMOOF9HW8R0MX5WESVXO3OZ5TJ2AP62L91B4PCUP5C1J`

   Web page where this is set:
   ```python
   captchaify = Captchaify(app, friendly_secret = '<secret>')
   ```
