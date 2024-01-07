from setuptools import setup, find_packages
try:
    from pip._internal.req import parse_requirements
except ImportError:
    from pip.req import parse_requirements

requirements = [str(requirement.requirement) for requirement in list(parse_requirements("requirements.txt", session=False))]

setup(
    name='flask_Captchaify',
    version='1.2.6',
    description='Protect against bots and DDoS attacks',
    author='TN3W',
    author_email='tn3wA8xxfuVMs2@proton.me',
    url='https://github.com/tn3w/flask_Captchaify',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    package_data={
        'flask_Captchaify': ['data/*', 'templates/*']
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
    install_requires=requirements
)
