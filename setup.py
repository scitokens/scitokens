
"""
Install file for SciTokens project.
"""

import os.path
import re

import setuptools

# read the contents of your README file
from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.rst").read_text()


def find_version(path, varname="__version__"):
    """Parse the version metadata variable in the given file.
    """
    with open(path, 'r') as fobj:
        version_file = fobj.read()
    version_match = re.search(
        r"^{0} = ['\"]([^'\"]*)['\"]".format(varname),
        version_file,
        re.M,
    )
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


setuptools.setup(
    # metadata
    name="scitokens",
    version=find_version(os.path.join("src", "scitokens", "__init__.py")),
    description="SciToken reference implementation library",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    author_email="team@scitokens.org",
    author="Brian Bockelman",
    license="Apache-2.0",
    url="https://scitokens.org",
    project_urls={
        "Issue Tracker": "https://github.com/scitokens/scitokens/issues",
        "Source Code": "https://github.com/scitokens/scitokens",
    },
    # contents
    package_dir={
        "": "src",
    },
    packages=[
        "scitokens",
        "scitokens.tools",
        "scitokens.utils",
    ],
    entry_points={
        "console_scripts": [
            "scitokens-admin-create-key=scitokens.tools.admin_create_key:main",
            "scitokens-admin-create-token=scitokens.tools.admin_create_token:main",
        ],
    },
    # requirements
    python_requires=">=3.5",
    install_requires=[
        'cryptography',
        'PyJWT>=1.6.1',
        'six',
        'setuptools'
    ],
    # classifiers
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Scientific/Engineering",
    ],
)
