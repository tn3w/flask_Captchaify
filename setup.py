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

long_description = long_description.split('<h1 align="center">𝐟𝐥𝐚𝐬𝐤_𝐂𝐚𝐩𝐭𝐜𝐡𝐚𝐢𝐟𝐲</h1>')[1]
long_description = '<h1 align="center">𝐟𝐥𝐚𝐬𝐤_𝐂𝐚𝐩𝐭𝐜𝐡𝐚𝐢𝐟𝐲</h1>' + long_description
long_description = long_description.split('### Some Screenshots')[0] +\
    '''### To-Do's''' + long_description.split('''### To-Do's''')[1]

long_description = long_description.replace('   - [Some Screenshots](#some-screenshots)\n', '')

setup(
    name='flask_Captchaify',
    version='1.7.1.2',
    description='Protect against bots and DDoS attacks',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='TN3W',
    author_email='tn3wA8xxfuVMs2@proton.me',
    url='https://github.com/tn3w/flask_Captchaify',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    package_data={
        'flask_Captchaify': ['assets/*', 'templates/*', 'datasets/*']
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
