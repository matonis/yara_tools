#!/usr/bin/env python
import os
from setuptools import setup, find_packages


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='yara_tools',
    version='0.1',
    description='Tool to interact with YARA',
    url="https://github.com/matonis/yara_tools",
    author='@matonis',
    author_email='',
    license='Buy me beer, burritos, and burgers.',
    packages=find_packages(),
    install_requires=[],
    long_description=open('README.md').read(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries'
    ],
    entry_points={
        'console_scripts': [
            'yara_tools = yara_tools.cli.client:main'
        ]
    },
    zip_safe=True,
    keywords=['yara', 'infosec', 'security'],
)
