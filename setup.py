#-------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation
# All rights reserved.
#
# Distributed under the terms of the MIT License
#-------------------------------------------------------------------------

import os
import setuptools

from setuptools import Extension
from Cython.Build import cythonize

EXT_MODULES = cythonize([
    Extension("winhttp._winhttp", ["winhttp/_winhttp.pyx"])
])

setup_cfg = dict(
    ext_modules=EXT_MODULES,
)

setuptools.setup(**setup_cfg)
