"""
⚒️ Setup module for flask_Captchaify

https://github.com/tn3w/flask_Captchaify
Made with 💩 in Germany by TN3W
"""

from setuptools import setup, find_packages
from pip._internal.req import parse_requirements

requirements = [str(requirement.requirement)\
                for requirement in list(parse_requirements("requirements.txt", session=False))]

with open('README.md', 'r', encoding='utf-8') as readable_file:
    long_description = readable_file.read()

long_description = long_description.split("# flask_Captchaify")[1]
long_description = '<p align="center"><a rel="noreferrer noopener" href="https://github.com/tn3w/'+\
                   'flask_Captchaify"><img alt="Github" src="https://img.shields.io/badge/Github-'+\
                    '141e24.svg?&style=for-the-badge&logo=github&logoColor=white"></a>  <a rel="n'+\
                    'oreferrer noopener" href="https://pypi.org/project/flask-Captchaify/"><img a'+\
                    'lt="PyPI" src="https://img.shields.io/badge/PyPi-141e24.svg?&style=for-the-b'+\
                    'adge&logo=python&logoColor=white"></a>  <a rel="noreferrer noopener" href="h'+\
                    'ttps://libraries.io/pypi/flask-Captchaify"><img alt="Libraries.io" src="http'+\
                    's://img.shields.io/badge/Libraries.io-141e24.svg?&style=for-the-badge&logo=n'+\
                    'pm&logoColor=white"></a>\n' + long_description
long_description = long_description.split("[^1]: Text and,")[0]
long_description = long_description.replace("[^1]", "").replace("[^2]", "")\
    .replace("[^3]", "").replace("[^4]", "").replace("> [!NOTE]", "")

setup(
    name='flask_Captchaify',
    version='1.6.7',
    description='Protect against bots and DDoS attacks',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='TN3W',
    author_email='tn3wA8xxfuVMs2@proton.me',
    url='https://github.com/tn3w/flask_Captchaify',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    package_data={
        'flask_Captchaify': ['assets/*', 'templates/*']
    },
    classifiers=[
        'Environment :: Web Environment',
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    license='GPL-3.0',
    keywords='flask, Python, Bot, Captcha, DDoS',
    install_requires=requirements
)
