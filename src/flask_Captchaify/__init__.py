import os
import json
import random
import requests
import pkg_resources
from time import time
from base64 import b64encode
from bs4 import BeautifulSoup
from captcha.image import ImageCaptcha
from captcha.audio import AudioCaptcha
from urllib.parse import urlparse, quote
from flask import Flask, request, g, abort, send_file, make_response, redirect
from typing import Optional
from .utils import JSON, generate_random_string, WebPage, get_client_ip, Hashing, SymmetricCrypto, get_ip_info

DATA_DIR = pkg_resources.resource_filename('flask_Captchaify', 'data')
TEMPLATE_DIR = pkg_resources.resource_filename('flask_Captchaify', 'templates')

CRAWLER_USER_AGENTS = ["Googlebot", "bingbot", "Yahoo! Slurp", "YandexBot", "Baiduspider", "DuckDuckGo-Favicons-Bot", "AhrefsBot", "SemrushBot", "MJ12bot", "BLEXBot", "SeznamBot", "Exabot", "AhrefsBot", "archive.org_bot", "Applebot", "spbot", "Genieo", "linkdexbot", "Lipperhey Link Explorer", "SISTRIX Crawler", "MojeekBot", "CCBot", "Uptimebot", "XoviBot", "Neevabot", "SEOkicks-Robot", "meanpathbot", "MojeekBot", "RankActiveLinkBot", "CrawlomaticBot", "sentibot", "ExtLinksBot", "Superfeedr bot", "LinkfluenceBot", "Plerdybot", "Statbot", "Brainity", "Slurp", "Barkrowler", "RanksonicSiteAuditor", "rogerbot", "BomboraBot", "RankActiveLinkBot", "mail.ru", "AI Crawler", "Xenu Link Sleuth", "SEMrushBot", "Baiduspider-render", "coccocbot", "Sogou web spider", "proximic", "Yahoo Link Preview", "Cliqzbot", "woobot", "Barkrowler", "CodiBot", "libwww-perl", "Purebot", "Statbot", "iCjobs", "Cliqzbot", "SafeDNSBot", "AhrefsBot", "MetaURI API", "meanpathbot", "ADmantX Platform Semantic Analyzer", "CrawlomaticBot", "moget", "meanpathbot", "FPT-Aibot", "Domains Project", "SimpleCrawler", "YoudaoBot", "SafeDNSBot", "Slurp", "XoviBot", "Baiduspider", "FPT-Aibot", "SiteExplorer", "Lipperhey Link Explorer", "CrawlomaticBot", "SISTRIX Crawler", "SEMrushBot", "meanpathbot", "sentibot", "Dataprovider.com", "BLEXBot", "YoudaoBot", "Superfeedr bot", "moget", "Genieo", "sentibot", "AI Crawler", "Xenu Link Sleuth", "Barkrowler", "proximic", "Yahoo Link Preview", "Cliqzbot", "woobot", "Barkrowler"]
EMOJIS = JSON.load(os.path.join(DATA_DIR, "emojis.json"))
TEAEMOJIS = JSON.load(os.path.join(DATA_DIR, "teaemojis.json"))
LANGUAGES = JSON.load(os.path.join(DATA_DIR, "languages.json"))
LANGUAGES_CODE = [language["code"] for language in LANGUAGES]

RATE_LIMIT_PATH = os.path.join(DATA_DIR, "rate-limits.json")
SFS_CACHE_PATH = os.path.join(DATA_DIR, "sfs-cache.json")
FAILED_CAPTCHAS_PATH = os.path.join(DATA_DIR, "failed-captchas.json")
SOLVED_CAPTCHAS_PATH = os.path.join(DATA_DIR, "solved-captchas.json")

class Captcha:
    """
    Shows the user/bot a captcha before the request first if the request comes from a dangerous IP
    Further function are: Rate Limits, Crawler Hints, Custom Templates, Rules for Specific Routes
    """

    def __init__ (
        self, app: Flask, actions: dict = {},
        hardness: dict = {}, rate_limits: dict = {}, template_dirs: dict = {},
        default_action: str = "captcha", default_hardness: int = 2, default_rate_limit: Optional[int] = 120, 
        default_max_rate_limit = 1200, default_template_dir: Optional[str] = None, verificationage: int = 3600,
        withoutcookies: bool = False, block_crawler: bool = True, crawler_hints: bool = True
        ):
        """
        Initialize the Captcha object

        :param app: Your Flask App
        :param actions: Dict with actions for different routes like here: {"urlpath": "fight", "endpoint": "block"}, e.g. {"/": "block", "*/api/*": "let", "/login": "fight"} which blocks all suspicious traffic to "/", allows all traffic to /api/ routes e. e.g. "/api/cats" or "/dogs/api/" if they contain "/api/", and where to "/login" any traffic whether suspicious or not has to solve a captcha. (Default = {})
        :param hardness: Dict with hardness for different routes like here: {"urlpath": 1, "endpoint": 2}, e.g. {"/": 3, "*/api/*": 1, "/login": 3}. The urlpaths have the same structure as for actions. (Default = {})
        :param rate_limits: Dict with rate limit and max rate limit for different routes, the rate limit variable indicates how many requests an ip can make per minute, the max rate limit variable specifies the maximum number of requests that can come from all Ips like here: {"urlpath": (180, 1800), "endpoint": (130, 1300)}, e.g. {"/": (120, 1200), "*/api/*": (180, 1800), "/login": (60, 600)}. The urlpaths have the same structure as for actions. (Default = {})
        :param template_dirs: Dict with template folder for different routes like here: {"urlpath": "/path/to/template/dir", "endpoint": "/path/to/template/dir2"}, e.g. {"/": "/path/to/template/dir", "*/api/*": "/path/to/myapi/template/dir", "/login": "/path/to/login/template/dir"}. The urlpaths have the same structure as for actions. (Default = {})
        :param default_action: The default value of all pages if no special action is given in actions. (Default = "captcha")
        :param default_hardness: The default value of all pages if no special hardness is given in hardness. (Default = 2)
        :param default_rate_limit: How many requests an ip can make per minute, if nothing is given at rate_limits this value is used. If None, no rate limit is set. (Default = 120)
        :param default_max_rate_limit: How many requests all Ips can make per minute, if nothing is given at rate_limits this value is used. If None, no max rate limit is set. (Default = 1200)
        :param default_template_dir: The default value of all pages if no special template_dir is given in template_dirs. (Default = None)
        :param verificationage: How long the captcha verification is valid, in seconds (Default = 3600 [1 hour])
        :param withoutcookies: If True, no cookie is created after the captcha is fulfilled, but only an Arg is appended to the URL (Default = False)
        :param block_crawler: If True, known crawlers based on their user agent will also need to solve a captcha (Default = False)
        :param crawler_hints: If True, crawlers will cache a page with no content only with meta content of the real web page that is already in the cache.
        """

        if app is None:
            raise ValueError("The Flask app cannot be None")

        if not isinstance(actions, dict):
            actions = dict()
        
        if not isinstance(hardness, dict):
            hardness = dict()
        
        if not isinstance(rate_limits, dict):
            rate_limits = {}
        
        if not isinstance(template_dirs, dict):
            template_dirs = dict()
        
        if not default_action in ["let", "block", "fight", "captcha"]:
            default_action = "captcha"
        
        if not default_hardness in [1, 2, 3]:
            default_hardness = 2

        if not isinstance(default_rate_limit, int) and not default_rate_limit is None:
            default_rate_limit = 120
        
        if not isinstance(default_max_rate_limit, int) and not default_max_rate_limit is None:
            default_max_rate_limit = 1200
        
        if default_template_dir is None:
            default_template_dir = TEMPLATE_DIR

        if not isinstance(verificationage, int):
            verificationage = 3600
        
        if not isinstance(withoutcookies, bool):
            withoutcookies = False
        
        if not isinstance(block_crawler, bool):
            block_crawler = True
        
        if not isinstance(crawler_hints, bool):
            crawler_hints = True
        
        self.app = app

        self.actions = actions
        self.hardness = hardness
        self.rate_limits = rate_limits
        self.template_dirs = template_dirs

        self.default_action = default_action
        self.default_hardness = default_hardness
        self.default_rate_limit = default_rate_limit
        self.default_max_rate_limit = default_max_rate_limit
        self.default_template_dir = default_template_dir

        self.verificationage = verificationage
        self.withoutcookies = withoutcookies
        self.block_crawler = block_crawler
        self.crawler_hints = crawler_hints

        self.CAPTCHA_SECRET = generate_random_string(32)

        if self.crawler_hints:
            self.crawler_hints_cache = dict()

        app.before_request(self._set_ip)
        app.before_request(self._rate_limit)
        app.before_request(self._change_language)
        app.before_request(self._fight_bots)

        app.after_request(self._add_rate_limit)
        if self.withoutcookies:
            app.after_request(self._add_args)
        else:
            app.after_request(self._set_cookies)

        if self.crawler_hints:
            app.after_request(self._crawler_hints)
    
    @property
    def _preferences(self):
        def is_correct_route(path: str):
            url_path = urlparse(request.url).path
            url_endpoint = request.endpoint

            url = url_path
            if not "/" in path:
                url = url_endpoint

            if '*' in path:
                real_path = path.replace("*", "")
                if (path.startswith("*") and path.endswith("*") and real_path in url) or \
                    (path.startswith("*") and url.endswith(real_path)) or \
                        (path.endswith("*") and url.startswith(real_path)):
                    return True
                first_part, second_part = path.split("*")[0], path.split("*")[1]

                if url.startswith(first_part) and url.endswith(second_part):
                    return True

            else:
                if path == url_endpoint:
                    return True
            
            return False

        current_url = {
            "action": self.default_action,
            "hardness": self.default_hardness,
            "rate_limit": self.default_rate_limit,
            "max_rate_limit": self.default_max_rate_limit,
            "template_dir": self.default_template_dir
        }

        preferences = [
            {"name": "action", "list": self.actions}, 
            {"name": "hardness", "list": self.hardness}, 
            {"name": "rate_limits", "list": self.rate_limits}, 
            {"name": "template_dir", "list": self.template_dirs}
        ]

        for preference in preferences:
            if len(preference["list"]) == 0:
                continue
            for path, path_preference in preference.items():
                if is_correct_route(path):
                    if preference["name"] != "rate_limits":
                        current_url[preference["name"]] = path_preference
                    else:
                        current_url["rate_limit"], current_url["max_rate_limit"] = path_preference
        
        return current_url
    
    def _correct_template(self, template_type: str, **args):
        if not template_type in ["captcha", "block", "rate_limited"]:
            raise Exception("'" + template_type + "' is not a Template Type.")
        
        template_dir = self._preferences["template_dir"]

        page_path = None

        for file in os.listdir(template_dir):
            if file.startswith(template_type):
                page_path = os.path.join(template_dir, file)
                break
        
        if page_path is None:
            return abort(404)
    
        page_ext = page_path.split('.')[-1]
        
        if page_ext == "html":
            html = WebPage.render_template(page_path, **args)
            return html
        elif page_ext == "json":
            with open(page_path, "r") as file:
                return JSON.load(file)
        elif page_ext in ["txt", "xml"]:
            with open(page_path, "r") as file:
                return file.read()
        else:
            return send_file(page_path)
        
    def _set_ip(self):
        g.captchaify_page = False
        g.is_crawler = False

        client_ip = get_client_ip()
        client_user_agent = request.user_agent.string

        if client_ip is None or client_user_agent is None:
            emoji = random.choice(EMOJIS)
            return self._correct_template("block", emoji = emoji)
        
        g.client_ip = client_ip
        g.client_user_agent = client_user_agent
        g.captchaify_captcha = None
    
    def _rate_limit(self):
        rate_limited_ips = JSON.load(RATE_LIMIT_PATH)

        preferences = self._preferences

        rate_limit = preferences["rate_limit"]
        max_rate_limit = preferences["max_rate_limit"]
        
        request_count = 0
        ip_request_count = 0

        for hashed_ip, ip_timestamps in rate_limited_ips.items():
            count = 0
            for request_time in ip_timestamps:
                if not int(time()) - int(request_time) > 60:
                    count += 1
            comparison = Hashing().compare(g.client_ip, hashed_ip)
            if comparison:
                ip_request_count += count
            request_count += count

        if (ip_request_count >= rate_limit and not rate_limit == 0) or \
            (request_count >= max_rate_limit and not max_rate_limit == 0):
            emoji = random.choice(TEAEMOJIS)
            return self._correct_template("rate_limited", emoji = emoji), 418
    
    def _change_language(self):
        if request.args.get("captchaify_changelanguage") == "1":
            languages = LANGUAGES

            search = None
            if not request.args.get("captchaify_search") is None:
                searchlanguages = []

                for lang in languages:
                    if request.args.get("captchaify_search").lower() in lang["name"].lower():
                        searchlanguages.append(lang)

                languages = searchlanguages
                search = request.args.get("captchaify_search")

            template_dir = self._preferences["template_dir"]

            for file in os.listdir(template_dir):
                if file.startswith("change_language") or file.startswith("changelanguage"):
                    return WebPage.render_template(os.path.join(template_dir, file), search=search, languages=languages)
                
    def _fight_bots(self):
        url_path = urlparse(request.url).path

        def add_failed_captcha():
            failed_captchas = JSON.load(FAILED_CAPTCHAS_PATH)

            is_found = False

            for hashed_ip, ip_records in failed_captchas.items():
                comparison = Hashing().compare(g.client_ip, hashed_ip)
                if comparison:
                    is_found = True

                    records_length = 0
                    for record in ip_records:
                        if not int(time()) - int(record) > 7200:
                            records_length += 1
                    records_length += 1

                    ip_records.append(str(int(time())))
                    failed_captchas[hashed_ip] = ip_records

                    JSON.dump(failed_captchas, FAILED_CAPTCHAS_PATH)

            if not is_found:
                hashed_client_ip = Hashing().hash(g.client_ip)
                failed_captchas[hashed_client_ip] = [str(int(time()))]

                JSON.dump(failed_captchas, FAILED_CAPTCHAS_PATH)
        
        def show_captcha(error: bool = False):
            captcha_token = Hashing().hash(url_path) + "-//-" + str(int(time())) + "-//-" + str(hardness) + "-//-" +\
                Hashing().hash(g.client_ip) + "-//-" + Hashing().hash(g.client_user_agent) + "-//-"

            string_length = (5 if hardness == 1 else 8 if hardness == 2 else 9) + random.choice([1, 1, 2, 3])
            
            image_captcha_code = generate_random_string(string_length, with_punctuation=False)

            if string_length > 6:
                image_captcha_code = image_captcha_code.upper()
            
            image_captcha = ImageCaptcha(width=320, height=120, fonts=[
                os.path.join(DATA_DIR, "Comic_Sans_MS.ttf"),
                os.path.join(DATA_DIR, "DroidSansMono.ttf"),
                os.path.join(DATA_DIR, "Helvetica.ttf")
            ])

            captcha_image = image_captcha.generate(image_captcha_code)

            captcha_image_data = b64encode(captcha_image.getvalue()).decode('utf-8')
            captcha_image_data = "data:image/png;base64," + captcha_image_data

            captcha_token += image_captcha_code

            captcha_audio_data = None

            if hardness == 3:
                int_length = 8 + random.choice([1, 2, 3, 4, 5, 6])

                audio_captcha_code = generate_random_string(int_length, with_punctuation=False, with_letters=False)
                audio_captcha = AudioCaptcha()
                captcha_audio = audio_captcha.generate(audio_captcha_code)

                captcha_audio_data = b64encode(captcha_audio).decode('utf-8')
                captcha_audio_data = "data:audio/wav;base64," + captcha_audio_data

                captcha_token += "-//-" + audio_captcha_code
            
            coded_captcha_token = SymmetricCrypto(self.CAPTCHA_SECRET).encrypt(captcha_token)

            error = "That was not right, try again!" if error else None

            return self._correct_template("captcha", error = error, textCaptcha=captcha_image_data, audioCaptcha = captcha_audio_data, captchatoken=coded_captcha_token)

        action = self._preferences["action"]
        hardness = self._preferences["hardness"]

        if action == "let":
            return

        is_crawler = False
        for crawlername in CRAWLER_USER_AGENTS:
            if crawlername.lower() in g.client_user_agent.lower():
                is_crawler = True
        
        g.is_crawler = is_crawler
        
        criteria = [
            is_crawler and self.block_crawler,
            action == "fight"
        ]

        if not any(criteria):
            if not g.client_ip == "127.0.0.1":
                try:
                    ip_info = get_ip_info(g.client_ip)
                except Exception as e:
                    criteria.append(True)
                else:
                    if ip_info["proxy"] or ip_info["hosting"]:
                        criteria.append(True)

        if not any(criteria):
            stopforumspamcache = JSON.load(SFS_CACHE_PATH)

            found = False
            
            for hashed_ip, ip_content in stopforumspamcache.items():
                comparison = Hashing().compare(g.client_ip, hashed_ip)
                if comparison:
                    found = True
                    
                    if ip_content["spammer"] and not int(time()) - int(ip_content["time"]) > 604800:
                        criteria.append(True)
                    break

            if not found:
                response = requests.get(f"https://api.stopforumspam.org/api?ip={g.client_ip}&json")
                if response.ok:
                    try:
                        content = response.json()
                    except:
                        criteria.append(True)
                    else:
                        spammer = False
                        if content["ip"]["appears"] > 0:
                            spammer = True
                            criteria.append(True)

                        hashed_client_ip = Hashing().hash(g.client_ip)

                        stopforumspamcache[hashed_client_ip] = {"spammer": spammer, "time": int(time())}
                        
                        JSON.dump(stopforumspamcache, SFS_CACHE_PATH)
                else:
                    criteria.append(True)
        
        if not any(criteria):
            return
        
        if action == "block":
            emoji = random.choice(EMOJIS)
            return self._correct_template("block", emoji = emoji)
        
        failed_captchas = JSON.load(FAILED_CAPTCHAS_PATH)

        for hashed_ip, ip_records in failed_captchas.items():
            comparison = Hashing().compare(g.client_ip, hashed_ip)
            if comparison:
                records_length = 0
                for record in ip_records:
                    if not int(time()) - int(record) > 14400:
                        records_length += 1
                if (action == "fight" or hardness == 3) and records_length > 2 or records_length > 3:
                    emoji = random.choice(EMOJIS)
                    return self._correct_template("block", emoji = emoji)
        
        is_failed_captcha = False
        
        if request.args.get("captchasolved") == "1":
            text_captcha = request.args.get("textCaptcha")
            audio_captcha = request.args.get("audioCaptcha")
            captcha_token = request.args.get("captchatoken")

            if not None in [text_captcha, captcha_token]:
                try:
                    captcha_token_decrypted = SymmetricCrypto(self.CAPTCHA_SECRET).decrypt(captcha_token)
                except:
                    pass
                else:
                    ct = captcha_token_decrypted.split('-//-')

                    ct_path, ct_time, ct_hardness, ct_ip, ct_useragent, ct_text = ct[0], ct[1], int(ct[2]), ct[3], ct[4], ct[5]

                    is_failing = False

                    if ct_hardness == 3:
                        ct_audio = ct[6]

                        if hardness == 3:
                            if audio_captcha is None:
                                is_failing = True
                            else:
                                if str(audio_captcha) != str(ct_audio):
                                    is_failing = True
                        else:
                            if not audio_captcha is None:
                                if not str(audio_captcha) != str(ct_audio):
                                    ct_hardness = hardness
                            else:
                                ct_hardness = hardness
                    
                    if not is_failing:
                        if not hardness < ct_hardness:
                            comparison_path = Hashing().compare(url_path, ct_path)
                            comparison_ip = Hashing().compare(g.client_ip, ct_ip)
                            comparison_user_agent = Hashing().compare(g.client_user_agent, ct_useragent)

                            if not comparison_path or \
                                int(time()) - int(ct_time) > 180 or \
                                    (not comparison_ip and not comparison_user_agent) or \
                                        str(text_captcha) != str(ct_text):
                                is_failed_captcha = True

                            else:
                                id = generate_random_string(16, with_punctuation=False)
                                token = generate_random_string(40)

                                solved_captchas = JSON.load(SOLVED_CAPTCHAS_PATH)
                                
                                while any([Hashing().compare(id, hashed_id) for hashed_id, _ in solved_captchas.items()]):
                                    id = generate_random_string(with_punctuation=False)

                                symcrypto = SymmetricCrypto(self.CAPTCHA_SECRET)

                                data = {
                                    "time": int(time()),
                                    "ip": symcrypto.encrypt(g.client_ip),
                                    "user_agent": symcrypto.encrypt(g.client_user_agent),
                                    "hardness": symcrypto.encrypt(str(ct_hardness))
                                }

                                solved_captchas = JSON.load(SOLVED_CAPTCHAS_PATH)
                                
                                solved_captchas[Hashing().hash(id)] = data

                                JSON.dump(solved_captchas, SOLVED_CAPTCHAS_PATH)

                                g.captchaify_captcha = id+token

                                if self.withoutcookies:
                                    return redirect(request.url.replace("http://", request.scheme + "://")\
                                        .replace("?textCaptcha=" + str(request.args.get("textCaptcha")), "").replace("&textCaptcha=" + str(request.args.get("textCaptcha")), "")\
                                        .replace("?audioCaptcha=" + str(request.args.get("audioCaptcha")), "").replace("&audioCaptcha=" + str(request.args.get("audioCaptcha")), "")\
                                        .replace("?captchatoken=" + str(request.args.get("captchatoken")), "").replace("&captchatoken=" + str(request.args.get("captchatoken")), "")\
                                        .replace("?captchasolved=1", "").replace("&captchasolved=1", "") + "?captcha=" + quote(g.captchaify_captcha))
                                return
                        else:
                            is_failed_captcha = True
                    else:
                        is_failed_captcha = True
            else:
                is_failed_captcha = True
        
        captcha_token = None
        if not request.args.get("captcha") is None:
            captcha_token = request.args.get("captcha")
        elif not request.cookies.get("captcha") is None:
            captcha_token = request.cookies.get("captcha")

        if captcha_token is None:
            if is_failed_captcha:
                add_failed_captcha()
            return show_captcha(error=is_failed_captcha)
        
        if len(captcha_token) != 56:
            if is_failed_captcha:
                add_failed_captcha()
            return show_captcha(error=is_failed_captcha)
            
        id, token = captcha_token[:16], captcha_token[16:]

        solved_captchas = JSON.load(SOLVED_CAPTCHAS_PATH)
       
        for hashed_id, ip_data in solved_captchas.items():
            comparison = Hashing().compare(id, hashed_id)
            if comparison:
                crypto = SymmetricCrypto(self.CAPTCHA_SECRET)
                datatime = ip_data["time"]
                try:
                    ip = crypto.decrypt(ip_data["ip"])
                    useragent = crypto.decrypt(ip_data["user_agent"])
                    captcha_hardness = int(crypto.decrypt(ip_data["hardness"]))
                except:
                    pass
                else:
                    if not int(time()) - int(datatime) > self.verificationage and hardness >= captcha_hardness:
                        if ip == g.client_ip and useragent == g.client_user_agent:
                            return
                break
        
        if is_failed_captcha:
            add_failed_captcha()

        return show_captcha(error=is_failed_captcha)

    def _add_rate_limit(self, response):
        rate_limit = self._preferences["rate_limit"]

        if not rate_limit == 0:
            rate_limited_ips = JSON.load(RATE_LIMIT_PATH)

            found = False
            for hashed_ip, ip_timestamps in rate_limited_ips.items():
                comparison = Hashing().compare(g.client_ip, hashed_ip)
                if comparison:
                    found = True

                    new_timestamps = []
                    for request_time in ip_timestamps:
                        if not int(time()) - int(request_time) > 60:
                            new_timestamps.append(request_time)
                    new_timestamps = [str(int(time()))] + new_timestamps

                    rate_limited_ips[hashed_ip] = new_timestamps[:round(rate_limit*1.2)]
                    break
            
            if not found:
                hashed_client_ip = Hashing().hash(g.client_ip, 16)
                rate_limited_ips[hashed_client_ip] = [str(int(time()))]
            
            JSON.dump(rate_limited_ips, RATE_LIMIT_PATH)
        
        return response

    def _set_cookies(self, response):
        response = make_response(response)
        if not g.captchaify_captcha is None:
            response.set_cookie("captcha", g.captchaify_captcha, max_age = self.verificationage, httponly = True, secure = self.app.config.get("HTTPS"))
        if request.args.get("captchaify_language") in LANGUAGES_CODE:
            response.set_cookie("language", request.args.get("captchaify_language"), max_age = 60*60*24*30*12*3, httponly = True, secure = self.app.config.get("HTTPS"))
        elif request.args.get("language") in LANGUAGES_CODE:
            response.set_cookie("language", request.args.get("language"), max_age = 60*60*24*30*12*3, httponly = True, secure = self.app.config.get("HTTPS"))
        elif request.cookies.get("language") in LANGUAGES_CODE:
            response.set_cookie("language", request.cookies.get("language"), max_age = 60*60*24*30*12*3, httponly = True, secure = self.app.config.get("HTTPS"))
        return response

    def _add_args(self, response):
        if response.content_type == "text/html; charset=utf-8":
            args = {}
            if not g.captchaify_captcha is None:
                args["captcha"] = g.captchaify_captcha
            elif not request.args.get("captcha") is None:
                args["captcha"] = request.args.get("captcha")

            if request.args.get("captchaify_language") in LANGUAGES_CODE:
                args["language"] = request.args.get("captchaify_language")
            elif request.args.get("language") in LANGUAGES_CODE:
                args["language"] = request.args.get("language")
            elif request.cookies.get("language") in LANGUAGES_CODE:
                args["language"] = request.cookies.get("language")

            html = response.data

            soup = BeautifulSoup(html, 'html.parser')

            for anchor in soup.find_all('a'):
                try:
                    if not anchor['href']:
                        continue
                except:
                    continue

                if "://" in anchor['href']:
                    anchor_host = urlparse(anchor['href']).netloc
                    if not anchor_host == request.host:
                        continue
                elif not anchor['href'].startswith("/") and \
                    not anchor['href'].startswith("#") and \
                        not anchor['href'].startswith("?") and \
                            not anchor['href'].startswith("&"):
                    continue

                for arg, content in args.items():
                    special_character = "?"
                    if "?" in anchor["href"]:
                        special_character = "&"
                    anchor['href'] = anchor['href'] + special_character + arg + "=" + quote(content)
                
            for form in soup.find_all("form"):
                added_input = ""
                for arg, content in args.items():
                    added_input += f'<input type="hidden" name="{arg}" value="{content}">'
                
                form_button = form.find('button')
                if form_button:
                    form_button.insert_before(added_input)
                else:
                    form.append(added_input)
                
                if "action" in form.attrs:
                    for arg, content in args.items():
                        special_character = "?"
                        if "?" in form['action']:
                            special_character = "&"
                        form['action'] = form['action'] + special_character + arg + "=" + quote(content)
        
            response.data = str(soup).replace("&lt;", "<").replace("&gt;", ">")
        
        return response
    
    def _crawler_hints(self, response):
        if not response.content_type == "text/html; charset=utf-8":
            return response

        path = request.path
        
        found = None

        copy_crawler_hints = self.crawler_hints_cache.copy()

        for hashed_path, path_data in self.crawler_hints_cache.items():
            comparison = Hashing().compare(path, hashed_path)
            if comparison:
                try:
                    decrypted_path_data = json.loads(SymmetricCrypto(path).decrypt(path_data))
                except:
                    del copy_crawler_hints[hashed_path]
                else:
                    if not int(time()) - int(decrypted_path_data["time"]) > 7200:
                        found = hashed_path
                    else:
                        del copy_crawler_hints[hashed_path]
                break

        symmetric_crypto = SymmetricCrypto(path)
        
        if found is None and not g.captchaify_page:
            html = response.data
            soup = BeautifulSoup(html, 'html.parser')

            title_tag = soup.title
            title = title_tag.string if title_tag else None
            og_tags = ''.join(str(og_tag) for og_tag in soup.find_all('meta', attrs={'property': 'og'}))

            hashed_path = Hashing().hash(path)

            copy_crawler_hints[hashed_path] = {
                "time": int(time()),
                "title": symmetric_crypto.encrypt(str(title)),
                "og_tags": symmetric_crypto.encrypt(og_tags)
            }

        if copy_crawler_hints != self.crawler_hints_cache:
            self.crawler_hints_cache = copy_crawler_hints
        
        if not found is None and g.captchaify_page:
            if g.is_crawler:
                html = response.data
                soup = BeautifulSoup(html, 'html.parser')

                title = symmetric_crypto.decrypt(self.crawler_hints_cache[found]["title"])
                if not title == "None":
                    soup.title.string = title

                og_soup = BeautifulSoup(symmetric_crypto.decrypt(self.crawler_hints_cache[found]["og_tags"]), 'html.parser')

                for tag in og_soup.find_all('meta'):
                    soup.head.append(tag)
                
                response = make_response(response)
        
        return response