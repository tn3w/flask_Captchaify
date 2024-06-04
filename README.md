<center>
   <picture align="center">
      <source width="1000px" media="(prefers-color-scheme: dark)" srcset="https://github.com/tn3w/flask_Captchaify/releases/download/img_v1.7/oneclick_dark.png">
      <source width="1000px" media="(prefers-color-scheme: light)" srcset="https://github.com/tn3w/flask_Captchaify/releases/download/img_v1.7/oneclick_light.png">
      <img width="1000px" alt="Picture from Block Page" src="https://github.com/tn3w/flask_Captchaify/releases/download/img_v1.7/oneclick_dark.png">
   </picture>
</center>
<h1 align="center">𝐟𝐥𝐚𝐬𝐤_𝐂𝐚𝐩𝐭𝐜𝐡𝐚𝐢𝐟𝐲</h1>
<p align="center"><a rel="noreferrer noopener" href="https://github.com/tn3w/flask_Captchaify"><img alt="Github" src="https://img.shields.io/badge/Github-141e24.svg?&style=for-the-badge&logo=github&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://pypi.org/project/flask-Captchaify/"><img alt="PyPI" src="https://img.shields.io/badge/PyPi-141e24.svg?&style=for-the-badge&logo=python&logoColor=white"></a>  <a rel="noreferrer noopener" href="https://libraries.io/pypi/flask-Captchaify"><img alt="Libraries.io" src="https://img.shields.io/badge/Libraries.io-141e24.svg?&style=for-the-badge&logo=npm&logoColor=white"></a></p>

<p align="center">A robust Captcha and Bot protection system tailored for Flask, packed with extra features including rate limiting, client-specific rules, crawler detection hints, and seamless automatic bot identification.</p>

<br>

```python
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
```


### How does it work?
In situations where it is deemed necessary, a captivating challenge may be presented to either the user or any automated agents, depending on the predetermined level of security required. Upon successful completion of this captivating challenge, a unique token is generated. This token serves as a secure vessel, encapsulating the client's information in an encrypted format. Subsequently, this token is deployed as both a cookie within the client's browser or as a parameter in the URL, denoted as 'captcha'. This mechanism ensures the continual validation of legitimacy with each subsequent request.


## Installation guide
1. Make sure you have the latest version of Python and Pip installed, you also need git installed.
2. Install the script with pip `pip install flask_Captchaify` or manually via `git clone https://github.com/tn3w/flask_Captchaify` or download the zip.
3. If you installed it manually, make sure your python script is in the folder where there is a subfolder flask_Captchaify, and make sure you run `pip install -r requirements.txt` in the flask_Captchaify folder.
4. Make sure that after:
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


## Personalization
### 1. `app` Arg

   A Flask() object of a Flask app that is modified by Captchaify so that each request is checked for bots

   Example:
   ```python
   from flask import Flask
   from flask_Captchaify import Captchaify

   app = Flask('MyWebsite')
   captchaify = Captchaify(app)
   ```


### 2. `rules` Arg

   Certain changes based on specific criteria such as IP, proxy, hosting or geo information

   Web page that blocks the localhost Ip:
   ```python
   captchaify = Captchaify(app, rules=[{"rule": ['ip', 'equals', '127.0.0.1'], "change": {"action": "block"}}])
   ```

   Criteria can also be combined, with 'and' meaning that both criteria must be met and 'or' meaning that one of the two criteria must be met:
   ```python
   rules = [{"rule": ['ip', 'is in', ['127.0.0.1', '10.0.0.1'], 'or', 'proxy', 'is', True]}, "change": {"action": "block"}]
   ```

   #### ~ Client Info ~

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

   All changes that can be made by these rules:
   | Name of the change | Type            | Example                |
   | ------------------ | --------------- | ---------------------- |
   | captcha_type       | str             | multiclick             |
   | action             | str             | allow                  |
   | rate_limit         | Tuple[int, int] | (20, 100)              |
   | template_dir       | str             | /path/to/template/dir  |


   #### ~ Asterik `*` ~
   The asterisk creates the customization options for information comparisons. The asterisk (*) serves as a wildcard, representing any number of characters including zero.

   Example of a rule that all routes that start with /login then have a string and then have /development as route e.g. `/login/api/development` or `/login/2fa/development`:
   ```python
   rules = [{"rule": ['path', 'is', '/login*/development']}, "change": {"action": "block"}]
   ```


   Here are all the things that can be changed:

   #### ~ Captcha types (`captcha_type`) ~
   | Name of captcha type | Displayed Captchas                                                        |
   | --------------       | ------------------------------------------------------------------------- |
   | oneclick (Default)   | The user only needs one click to confirm that he is not a bot             |
   | multiclick           | The user must select several images that match a motif (harder)           |
   | text                 | The user enters a text combination from an image into an input (obsolete) |
   | audio                | The user enters a text combination from an audio into an input (obsolete) |
   | text&audio           | The user enters a text and an audio combination into an input (obsolete)  |

   To specify the exact data set, you have to add it after the captcha_type with a `_` as separator, e.g. `oneclick_animals` or if you use a custom data set: `oneclick_custom`. If you use a text or audio captcha, you do not need a data set.

   Here are all the ready-made data sets:
   | Name of dataset | Displayed Captchas                                                                                 |
   | --------------- | -------------------------------------------------------------------------------------------------- |
   | keys            | Displays images based on specific keywords of landscapes, objects, and more (default for oneclick) |
   | animals         | Displays 50 different animal species (default for multiclick)                                      |


   #### ~ Actions (`action`) ~
   | Name of action | Executing Action                                                     |
   | -------------- | -------------------------------------------------------------------- |
   | allow          | Allows all traffic through, regardless of whether the IP is blocked. |
   | block          | Blocks all traffic if it is blocked, without captcha.                |
   | fight          | Displays a captcha to all traffic, whether suspicious or not.        |
   | captcha        | Default value, shows only suspicious traffic captchas.               |


   #### ~ Rate Limits (`rate_limit`) ~
   The syntax is a bit different from the others, because two values are specified `(rate_limit, max_rate_limit)`. The variable rate_limit must be a number indicating how many requests per minute can come from a given ip. max_rate_limit indicates how many requests can come from all ips per minute, also a number.


   #### ~ Template Dir (`template_dir`) ~
   To change the template directory of a particular route use the template_dirs arg.

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


### 3. `dataset_size` Arg

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
   It is recommended that you generate your own dataset as the default data could be trained, use the script written in `src/flask_Captchaify/datasets` and put the file in a folder and use the `dataset_dir` Arg to use it.

   Example of a website that uses 100 images per keyword and 140 keywords:
   ```python
   captchaify = Captchaify(app, dataset_size=(100, 140))
   ```


### 4. `dataset_dir` Arg

   Specifies where the program can find data sets.

   Example of a website that specifies its own dataset folder:
   ```python
   captchaify = Captchaify(app, dataset_dir='/path/to/my/dataset')
   ```

   A data set should be a json file and have the following names in the folder:
   ```
   dataset_dir\
          \keys.json
   ```


### 5. `default_captcha_type` Arg

   To specify the default captcha type of all routes or endpoints use the default_captcha_type arg.

   Example of a website that has set its types to "text" (for text bases captchas) for all routes:
   ```python
   captchaify = Captchaify(app, default_captcha_type="text")
   ```

### 6. `default_action` Arg

   To specify the default action of all routes or endpoints use the default_action arg.

   Example of a very paranoid website that has set its action to "fight" for all routes:
   ```python
   captchaify = Captchaify(app, default_action="fight")
   ```

### 7. `default_rate_limit` Arg

   To specify the default requests of an IP per minute for all routes use the default_rate_limit variable. (Default: 120 = 2 requests per second per IP)

   Example of a web page with custom rate_limit:
   ```python
   captchaify = Captchaify(app, default_rate_limit=60)
   ```

### 8. `default_max_rate_limit` Arg

   To specify the default requests of all IPs per minute for all routes use the default_max_rate_limit variable. (Default: 1200 = 2 requests per second from 10 IPs)

   Example of a web page with custom max_rate_limit:
   ```python
   captchaify = Captchaify(app, default_max_rate_limit=600)
   ```


### 9. `default_template_dir` Arg

   To specify the default template_dir of all routes or endpoints use the default_template_dir arg.

   Example of a web page with custom template_dir:
   ```python
   captchaify = Captchaify(app, default_template_dir="/path/to/my/custom/template/directory")
   ```


### 10. `verification_age` Arg

   Indicates the time in seconds how long a solved captcha is valid (Default: 3600 = 1 hour)

   Website with 3 hours verification_age:
   ```python
   captchaify = Captchaify(app, verification_age=10800)
   ```


### 11. `without_cookies` Arg

   If True, no cookies are created, and verification is proven via URL args (Default: False)

   Website with without_cookies enabled:
   ```python
   captchaify = Captchaify(app, without_cookies=True)
   ```

### 12. `block_crawler` Arg

   If True, crawlers like Googlebot, further are estimated via their user agent as suspicious and not the website, good for websites that should not be crawled (Default: True)

   Web page with block_crawler enabled:
   ```python
   captchaify = Captchaify(app, block_crawler=True)
   ```


### 13. `crawler_hints` Arg:

   If True, crawlers like Googlebot, are shown meta tags and the title of a normal web page, while they would have to solve a captcha. (Default: True)
   
   Web page with crawler_hints disabled:
   ```python
   captchaify = Captchaify(app, crawler_hints=False)
   ```


### 14. `third_parties` Arg:

   Specifies which third parties are used to check the IP addresses. By default, all 3 third parties are used. (See list)

   Web page that only asks a third party for Tor Ip addresses:
   ```python
   captchaify = Captchaify(app, third_parties=["tor"])
   ```

   Possible entries would be:
   | Abbreviation         | Who is requested and how does the evaluation mechanism work?                                                                           |
   | -------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
   | tor                  | Uses dnspython to check if an IP is a Tor Exit Node. See [Stackoverflow #78535126](https://stackoverflow.com/questions/78535126/is-there-a-way-to-find-out-if-a-particular-ip-is-coming-from-tor-or-acting-as-a)|
   | ipapi                | [Ipapi](https://ipapi.com) is requested with the Ip and the result of the fields "proxy" and "hosting" is used                         |
   | stopforumspam        | [StopForumSpam](https://stopforumspam.com) is requested and the result is used                                                         |


### 15. `as_route` Arg:

   Specifies whether Captchaify pages are displayed as separate routes in order not to confuse the cache between normal pages and Captchaify pages (e.g. for Cloudflare)

   Web page where this is activated:
   ```python
   captchaify = Captchaify(app, as_route = True)
   ```


### 16. `without_other_args` Arg:

   After solving the captcha, arguments such as language and theme are deleted from the url bar

   Web page where this is activated:
   ```python
   captchaify = Captchaify(app, without_other_args = True)
   ```

### 17. `allow_customization` Arg:

   If True, the user can change their language or theme via pages or an anchor. However, these are normally detected automatically.
   If activated, protects less against DDOS attacks against flask_Captchaify websites such as Change Language (not recommended).

   Web page where this is activated:
   ```python
   captchaify = Captchaify(app, allow_customization = True)
   ```

## To-Do's
- [x] Captcha or blocking rules based on client_ip and client_ip_info (e.g. blocking of certain IP countries)
- [x] add `*` to rules Arg
- [x] https://github.com/tn3w/flask_Captchaify/issues/9 fixed with https://github.com/tn3w/flask_Captchaify/commit/3426b8fdafdc938c4951012a0dadf80b96b01776
- [ ] Captcha data set with emojis