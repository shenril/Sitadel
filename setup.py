#!/usr/bin/env python
from setuptools import setup

from lib import __version__

tests_require = [
    'pytest',
    'flake8'
]

setup(
    name='Sitadel',
    version=__version__,
    packages=[  'lib',
                'lib.utils',
                'lib.config',
                'lib.modules',
                'lib.modules.crawler',
                'lib.modules.attacks',
                'lib.modules.attacks.bruteforce',
                'lib.modules.attacks.injection',
                'lib.modules.attacks.vulns',
                'lib.modules.attacks.other',
                'lib.modules.fingerprints',
                'lib.modules.fingerprints.cdn',
                'lib.modules.fingerprints.cms',
                'lib.modules.fingerprints.framework',
                'lib.modules.fingerprints.frontend',
                'lib.modules.fingerprints.header',
                'lib.modules.fingerprints.lang',
                'lib.modules.fingerprints.server',
                'lib.modules.fingerprints.system',
                'lib.modules.fingerprints.waf',
                'lib.request'],
    scripts=['sitadel.py'],
    include_package_data=True,
    url='https://github.com/shenril/Sitadel',
    license='GPL-3.0-or-later',
    author='Shenril',
    author_email='florent.batard@gmail.com',
    description='Sitadel Web Application Scanner',
    python_requires=">=3.5",
    keywords='sitadel, security, scanner, web, python3',
    classifiers=[
        'Topic :: Security',
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Operating System :: POSIX :: Linux',
    ],
    install_requires=[
        "requests",
        "urllib3",
        # PyYAML < 5.3 references collections.Hashable, which was removed in
        # Python 3.10, crashing config loading. Require a version that works
        # on modern Python (see issue #47).
        "pyyaml>=6.0",
        "colorama",
        "scrapy"
    ],
    extras_require={
        'tests': tests_require,
    },
)
