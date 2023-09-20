#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : setup.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Sep 2023

import setuptools

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [x.strip() for x in f.readlines()]

setuptools.setup(
    name="rdwatool",
    version="2.0",
    description="",
    url="https://github.com/p0dalirius/RDWAtool",
    author="Podalirius",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author_email="podalirius@protonmail.com",
    packages=["rdwatool", "rdwatool.modes", "rdwatool.modes.recon", "rdwatool.modes.brute", "rdwatool.modes.spray"],
    package_data={'rdwatool': ['rdwatool/', 'rdwatool/modes/']},
    include_package_data=True,
    license="GPL2",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'rdwatool=rdwatool.__main__:main'
        ]
    }
)