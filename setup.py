#!/usr/bin/python
import sys

try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    from setuptools import setup, find_packages

version = '0.1'

setup(
    name='pyupnp',
    version=version,
    description='Python UPnP Library',
    author='Takashi Ito',
    author_email='itot@users.sourceforge.jp',
    url='http://code.google.com/p/pyupnp/',
    packages=find_packages(),
    keywords='upnp dlna wsgi twisted',
    license='BSD',
    zip_safe=True,
    install_requires=[
        'Twisted>=8.1.0',
        'zope.interface>=3.0.0',
        'Routes>=1.8',
        'Paste>=1.6',
    ],
)

