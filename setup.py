#!/usr/bin/python
import sys

try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    from setuptools import setup, find_packages

version = '0.2.2'

setup(
    name='pyupnp',
    version=version,
    description='Python UPnP Library',
    author='Takashi Ito',
    author_email='itot@users.sourceforge.jp',
    url='http://code.google.com/p/pyupnp/',
    keywords='upnp dlna wsgi twisted',
    license='BSD',
    zip_safe=True,
    packages=find_packages(),
    package_data={
        'pyupnp': ['xml/*.xml'],
    },
    setup_requires=[
        'Twisted>=8.2.0',
        'zope.interface',
        'Routes',
        'Paste',
        'WebOb',
    ],
    install_requires=[
        'Twisted>=8.2.0',
        'zope.interface',
        'Routes',
        'Paste',
        'WebOb',
    ],
)

