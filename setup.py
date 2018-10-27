#-------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation
# All rights reserved.
#
# Distributed under the terms of the MIT License
#-------------------------------------------------------------------------

import re
import setuptools
import sys

from Cython.Build import cythonize

__author__ = 'Microsoft Corporation <python@microsoft.com>'
__version__ = '0.1.0'

AUTHOR_RE = re.match(r'(.+?)\s*\<(.+?)\>', __author__)

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

PACKAGES = ['winhttp']
PACKAGE_DATA = {}
EXT_MODULES = cythonize("src/winhttp/_winhttp.pyx")
REQUIREMENTS = []
ENTRY_POINTS = []

CLASSIFIERS = [
    'Development Status :: 3 - Alpha',
    'Environment :: Win32 (MS Windows)',
    'License :: OSI Approved :: MIT License',
    'Natural Language :: English',
    'Operating System :: Microsoft :: Windows',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3 :: Only',
]

setup_cfg = dict(
    name='pyfindvs',
    version=__version__,
    description='Python module for using WinHttp',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author=AUTHOR_RE.group(1),
    author_email=AUTHOR_RE.group(2),
    url='https://github.com/zooba/winhttp',
    packages=PACKAGES,
    package_data=PACKAGE_DATA,
    ext_modules=EXT_MODULES,
    install_requires=REQUIREMENTS,
    classifiers=CLASSIFIERS,
    entry_points=ENTRY_POINTS,
)

from setuptools import setup
setup(**setup_cfg)
