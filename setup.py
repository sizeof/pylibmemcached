#!/usr/bin/env python
from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

setup(
    name = "pylibmemcached",
    version = "0.1.0",
    description="Python wrapper for libmemcached, a C client library to the Memcached server",
    maintainer="sizeof",
    maintainer_email="sizeof@sent.com",
    cmdclass = {'build_ext': build_ext},
    ext_modules=[Extension('pylibmemcached', ['pylibmemcached.pyx'],
        libraries=['memcached'],
    )]
)