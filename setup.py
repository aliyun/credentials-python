"""
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
"""

import os
import re
import sys
from setuptools import setup, find_packages

"""
Setup module for tea credentials.
Created on 3/24/2020
@author: Alibaba Cloud
"""

PACKAGE = "alibabacloud_credentials"
DESCRIPTION = "The alibabacloud credentials module of alibabaCloud Python SDK."
AUTHOR = "Alibaba Cloud"
AUTHOR_EMAIL = "alibaba-cloud-sdk-dev-team@list.alibaba-inc.com"
URL = "https://github.com/aliyun/credentials-python"
TOPDIR = os.path.dirname(__file__) or "."

def read_version():
    init_path = os.path.join(TOPDIR, PACKAGE, "__init__.py")
    with open(init_path, encoding="utf-8") as f:
        m = re.search(r'^__version__\s*=\s*[\'"]([^\'"]+)[\'"]', f.read(), re.M)
        if not m:
            raise RuntimeError("Cannot find __version__ in {}".format(os.path.relpath(init_path)))
        return m.group(1)

VERSION = read_version()

with open(os.path.join(TOPDIR, "README.md"), encoding="utf-8") as fp:
    LONG_DESCRIPTION = fp.read()

install_requires = [
    'alibabacloud-tea>=0.4.0',
    'alibabacloud_credentials_api>=1.0.0, <2.0.0'
]

if sys.version_info.minor <= 8:
    install_requires.append('APScheduler>=3.10.0, <3.11.0')
    install_requires.append('aiofiles>=22.1.0, <24.0.0')
    install_requires.append('tzlocal<5.3')
else:
    install_requires.append('APScheduler>=3.10.0, <4.0.0')
    install_requires.append('aiofiles>=22.1.0, <25.0.0')

setup_args = {
    'version': VERSION,
    'description': DESCRIPTION,
    'long_description': LONG_DESCRIPTION,
    'long_description_content_type': 'text/markdown',
    'author': AUTHOR,
    'author_email': AUTHOR_EMAIL,
    'license': "Apache License 2.0",
    'url': URL,
    'keywords': ["alibabacloud", "sdk", "tea"],
    'packages': find_packages(exclude=["tests*"]),
    'platforms': 'any',
    'python_requires': '>=3.7',
    'install_requires': install_requires,
    'classifiers': (
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Software Development',
    )
}

setup(name='alibabacloud-credentials', **setup_args)
