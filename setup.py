AUTHOR = 'Chris Dent'
AUTHOR_EMAIL = 'cdent@peermore.com'
NAME = 'tiddlywebplugins.remotebag'
DESCRIPTION = 'Access remote content as a bag'
VERSION = '0.7'


import os

from setuptools import setup, find_packages


setup(
    namespace_packages = ['tiddlywebplugins'],
    name = NAME,
    version = VERSION,
    description = DESCRIPTION,
    long_description = open(os.path.join(os.path.dirname(__file__),
        'README')).read(),
    author = AUTHOR,
    author_email = AUTHOR_EMAIL,
    url = 'http://pypi.python.org/pypi/%s' % NAME,
    platforms = 'Posix; MacOS X; Windows',
    packages = find_packages(exclude=['test']),
    install_requires = ['setuptools',
        'tiddlywebplugins.utils',
        'tiddlyweb>=1.2.39',
        'simplejson',
        'httplib2'],
    zip_safe = False
    )
