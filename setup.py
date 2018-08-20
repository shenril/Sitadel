from setuptools import setup

from lib import __version__

tests_require = [
    'pytest',
    'flake8'
]

setup(
    name='Sitadel',
    version=__version__,
    packages=['lib.utils', 'lib.config', 'lib.modules', 'lib.modules.attacks', 'lib.modules.fingerprints',
              'lib.request'],
    url='https://github.com/shenril/Sitadel',
    license='GNU GENERAL PUBLIC LICENSE Version 3',
    author='Shenril',
    author_email='florent.batard@gmail.com',
    description='Sitadel Web Application Scanner',
    python_requires=">=3.5",
    keywords='linguini, security, scanner, web, python3',
    classifiers=[
        'Topic :: Security',
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Operating System :: POSIX :: Linux',
    ],
    install_requires=[
        "requests",
        "urllib3",
        "pyyaml",
        "colorama",
        "scrapy"
    ],
    extras_require={
        'tests': tests_require,
    },
)
