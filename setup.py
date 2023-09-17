from setuptools import setup, find_packages

setup(
    name='flask_DDoSify',
    version='1.1',
    description='Protect against bots and DDoS attacks',
    long_description='A DDoS defense system for flask applications, first sends users to a captcha page without a javascript script and creates a confirmation cookie/url arg after the captcha.',
    author='TN3W',
    author_email='tn3wA8xxfuVMs2@proton.me',
    url='https://github.com/tn3w/flask_DDoSify',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    package_data={
        'flask_DDoSify': ['data/*', 'templates/*']
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
    keywords='flask, Python, Bot, Captcha, DDoS',
    install_requires=[
        'cryptography',
        'Flask',
        'googletrans==3.1.0a0',
        'beautifulsoup4',
        'ipaddress',
        'Jinja2',
        'Pillow',
        'requests',
        'bs4',
        'captcha',
    ],
)
